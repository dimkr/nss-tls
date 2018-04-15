/* This file is part of nss-tls.
 *
 * Copyright (C) 2018  Dima Krasner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdlib.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib-unix.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <libsoup/soup.h>
#include <json-glib/json-glib.h>

#include "nss-tls.h"

struct nss_tls_session {
    struct nss_tls_req request;
    struct nss_tls_res response;
    gint64 type;
    GSocketConnection *connection;
    SoupSession *session;
    SoupMessage *message;
};

static
void
on_close (GObject       *source_object,
          GAsyncResult  *res,
          gpointer      user_data)
{
    struct nss_tls_session *session = (struct nss_tls_session *)user_data;

    g_io_stream_close_finish (G_IO_STREAM (source_object), res, NULL);

    if (session->session) {
        soup_session_abort (session->session);
        g_object_unref (session->session);
    }

    g_object_unref (session->connection);
    g_free (session);
}

static
void
stop_session (struct nss_tls_session *session)
{
    g_io_stream_close_async (G_IO_STREAM (session->connection),
                             G_PRIORITY_DEFAULT,
                             NULL,
                             on_close,
                             session);
}

/* step 4: we're done sending the response to libnss_tls */
static
void
on_sent (GObject         *source_object,
         GAsyncResult    *res,
         gpointer        user_data)
{
    struct nss_tls_session *session = (struct nss_tls_session *)user_data;
    gsize out;

    if (g_output_stream_write_all_finish (G_OUTPUT_STREAM (source_object),
                                          res,
                                          &out,
                                          NULL) &&
        (out == sizeof (session->response))) {
        g_debug ("Done querying %s (%hhu results)",
                 session->request.name,
                 session->response.count);
    }
    else {
        g_debug ("Failed to query %s", session->request.name);
    }

    stop_session (session);
}

static
void
on_answer (JsonArray    *array,
           guint        index_,
           JsonNode     *element_node,
           gpointer     user_data)
{
    struct nss_tls_session *session = (struct nss_tls_session *)user_data;
    JsonObject *answero;
    const gchar *data;
    void *dst = &session->response.addrs[session->response.count].in;
    gint64 type;

    if (session->response.count >= NSS_TLS_ADDRS_MAX) {
        return;
    }

    answero = json_node_get_object (element_node);

    if (!json_object_has_member (answero, "type")) {
        g_warning ("No type member for %s", session->request.name);
        return;
    }

    /* if the type doesn't match, it's OK - continue to the next answer */
    type = json_object_get_int_member (answero, "type");
    if (type != session->type) {
        return;
    }

    if (!json_object_has_member (answero, "data")) {
        g_debug ("No data for answer %u of %s", index_, session->request.name);
        return;
    }

    data = json_object_get_string_member (answero, "data");
    if (!data) {
        g_debug ("Invalid data for answer %u of %s",
                 index_,
                 session->request.name);
        return;
    }

    if (session->request.af == AF_INET6) {
        dst = &session->response.addrs[session->response.count].in6;
    }

    if (inet_pton (session->request.af, data, dst)) {
        g_debug ("%s[%hhu] = %s",
                 session->request.name,
                 session->response.count,
                 data);
        ++session->response.count;
    }
}

/* step 3: we received the HTTPS response, parse it to construct our response
 * and send it to libnss_tls */
static
void
on_response (GObject         *source_object,
             GAsyncResult    *res,
             gpointer        user_data)
{
    GError *err = NULL;
    struct nss_tls_session *session = (struct nss_tls_session *)user_data;
    GInputStream *in;
    JsonParser *j = NULL;
    JsonNode *root;
    JsonObject *rooto;
    JsonArray *answers;
    GOutputStream *out;

    in = soup_session_send_finish (SOUP_SESSION (source_object),
                                   res,
                                   &err);
    if (!in) {
        if (err) {
            g_warning ("Failed to session %s: %s",
                       session->request.name,
                       err->message);
        }
        else {
            g_warning ("Failed to session %s", session->request.name);
        }
        goto cleanup;
    }

    j = json_parser_new ();
    if (!json_parser_load_from_stream (j, in, NULL, &err)) {
        if (err) {
            g_warning ("Failed to parse the result for %s: %s",
                       session->request.name,
                       err->message);
        }
        else {
            g_warning ("Failed to parse the result for %s",
                       session->request.name);
        }
        goto cleanup;
    }

    root = json_parser_get_root (j);
    rooto = json_node_get_object (root);
    if (!rooto) {
        g_warning ("No root object for %s", session->request.name);
        goto cleanup;
    }

    if (!json_object_has_member (rooto, "Answer")) {
        g_warning ("No Answer member for %s", session->request.name);
        goto cleanup;
    }
    answers = json_object_get_array_member (rooto, "Answer");

    session->response.count = 0;
    json_array_foreach_element (answers, on_answer, session);

    if (session->response.count > 0) {
        out = g_io_stream_get_output_stream (G_IO_STREAM (session->connection));
        g_output_stream_write_all_async (out,
                                         &session->response,
                                         sizeof (session->response),
                                         G_PRIORITY_DEFAULT,
                                         NULL,
                                         on_sent,
                                         session);
    }

cleanup:
    if (j) {
        g_object_unref (j);
    }

    if (err) {
        g_error_free (err);
    }

    if (in) {
        g_object_unref (in);
    }

    g_object_unref (session->message);
    session->message = NULL;

    if (session->response.count == 0) {
        stop_session (session);
    }
    else {
        /* if we found any addresses, we close the session now instead of doing
         * this in stop_session() once we're done sending passing the results to
         * the client, to keep the number of open file descriptors as low as
         * possible */
        g_object_unref (session->session);
        session->session = NULL;
    }
}

/* step 2: we received a request from libnss_tls and send a HTTPS request */
static
void
on_request (GObject         *source_object,
            GAsyncResult    *res,
            gpointer        user_data)
{
    GError *err = NULL;
    gchar *url;
    struct nss_tls_session *session = user_data;
    gsize len;

    session->session = NULL;
    session->message = NULL;

    if (!g_input_stream_read_all_finish (G_INPUT_STREAM (source_object),
                                         res,
                                         &len,
                                         &err)) {
        if (err) {
            g_warning ("Failed to receive a request: %s", err->message);
            g_error_free (err);
        }
        else {
            g_warning ("Failed to receive a request");
        }
        goto fail;
    }

    if (len != sizeof (session->request)) {
        g_debug ("Bad request");
        goto fail;
    }

    session->request.name[sizeof (session->request.name) - 1] = '\0';
    g_debug ("Querying %s", session->request.name);

    switch (session->request.af) {
    case AF_INET:
        /* A */
        session->type = 1;
        url = g_strdup_printf ("https://"NSS_TLS_RESOLVER"/dns-session?ct=application/dns-json&name=%s&type=A",
                               session->request.name);
        break;

    case AF_INET6:
        /* AAAA */
        session->type = 28;
        url = g_strdup_printf ("https://"NSS_TLS_RESOLVER"/dns-session?ct=application/dns-json&name=%s&type=AAAA",
                               session->request.name);
        break;

    default:
        goto fail;
    }

    g_debug ("Fetching %s", url);

    session->session = soup_session_new_with_options (SOUP_SESSION_TIMEOUT,
                                                      NSS_TLS_TIMEOUT,
                                                      SOUP_SESSION_IDLE_TIMEOUT,
                                                      NSS_TLS_TIMEOUT,
                                                      SOUP_SESSION_USER_AGENT,
                                                      NSS_TLS_USER_AGENT,
                                                      NULL);
    session->message = soup_message_new ("GET", url);

    soup_session_send_async (session->session,
                             session->message,
                             NULL,
                             on_response,
                             session);
    g_free (url);

    return;

fail:
    stop_session (session);
}

/* step 1: we accept a new connection from libnss_tls and wait for it to send a
 * request */
static
void
on_connection (GSocketService     *service,
               GSocketConnection  *connection,
               GObject            *source_object,
               gpointer           user_data)
{
    GSocket *s;
    struct nss_tls_session *session;
    GInputStream *in;

    /* we disconnect the client after NSS_TLS_TIMEOUT seconds */
    s = g_socket_connection_get_socket (connection);
    g_socket_set_timeout (s, NSS_TLS_TIMEOUT);

    session = g_new0 (struct nss_tls_session, 1);
    session->connection = g_object_ref (connection);

    in = g_io_stream_get_input_stream (G_IO_STREAM (connection));
    /* read the incoming request */
    g_input_stream_read_all_async (in,
                                   &session->request,
                                   sizeof (session->request),
                                   G_PRIORITY_DEFAULT,
                                   NULL,
                                   on_request,
                                   session);
}

static
gboolean
on_term (gpointer user_data)
{
    g_main_loop_quit ((GMainLoop *)user_data);
    return FALSE;
}

int main(int argc, char **argv)
{
    GMainLoop *loop;
    GSocketService *s;
    GSocketAddress *sa;

    g_unlink (NSS_TLS_SOCKET);
    sa = g_unix_socket_address_new (NSS_TLS_SOCKET);
    s = g_socket_service_new ();
    loop = g_main_loop_new (NULL, FALSE);

    g_socket_listener_add_address (G_SOCKET_LISTENER (s),
                                   sa,
                                   G_SOCKET_TYPE_STREAM,
                                   0,
                                   NULL,
                                   NULL,
                                   NULL);

    g_signal_connect (s,
                      "incoming",
                      G_CALLBACK (on_connection),
                      NULL);
    g_socket_service_start (s);
    g_chmod (NSS_TLS_SOCKET , 0666);

    g_unix_signal_add (SIGINT, on_term, loop);
    g_unix_signal_add (SIGTERM, on_term, loop);

    g_main_loop_run(loop);

    g_main_loop_unref(loop);
    g_object_unref(s);
    g_unlink (NSS_TLS_SOCKET);
    g_object_unref(sa);

    return EXIT_SUCCESS;
}
