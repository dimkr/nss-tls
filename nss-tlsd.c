/*
 * This file is part of nss-tls.
 *
 * Copyright (C) 2018, 2019  Dima Krasner
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
#include <sys/types.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <resolv.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <glib-unix.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <gmodule.h>
#include <libsoup/soup.h>

#include "nss-tls.h"

#define CACHE_CLEANUP_INTERVAL 5
#define FALLBACK_TTL (60 * 1000000)
#define MIN_TTL 10
#define CACHE_SIZE 1024
#define MAX_CONNS_PER_RESOLVER 10
#define MAX_CONNS MAX_CONNS_PER_RESOLVER * G_N_ELEMENTS (urls)

struct nss_tls_session {
    unsigned char dns[UINT16_MAX];
    struct nss_tls_req request;
    struct nss_tls_res response;
    gint64 type;
    GSocketConnection *connection;
    SoupMessage *message;
    gboolean canon;
};

static SoupSession *soup = NULL;
static const gchar *urls[] = {NSS_TLS_RESOLVER_URLS};
static const char *domains[] = {NSS_TLS_RESOLVER_DOMAINS};

#ifdef NSS_TLS_CACHE

static GHashTable *caches[2] = {NULL, NULL};

static
gboolean
check_ttl (gpointer key,
           gpointer value,
           gpointer user_data)
{
    const gchar *name = (const gchar *)key;
    struct nss_tls_res *res = (struct nss_tls_res *)value;
    gint64 now = *(gint64 *)user_data;

    if (now > res->expiry) {
        g_debug ("Cache for %s has expired", name);
        return TRUE;
    }

    return FALSE;
}

static
gboolean
on_cache_cleanup (gpointer user_data)
{
    gint64 now;
    gint i;

    now = g_get_monotonic_time ();

    for (i = 0; i < G_N_ELEMENTS (caches); ++i) {
        g_hash_table_foreach_remove (caches[i], check_ttl, &now);
    }

    return TRUE;
}

static
GHashTable *
choose_cache (const int af)
{
    if (af == AF_INET) {
        return caches[0];
    }

    return caches[1];
}

static
void
add_to_cache (const struct nss_tls_req *req, struct nss_tls_res *res)
{
    gchar *key;
    struct nss_tls_res *val;
    gint64 now;
    GHashTable *cache;

    cache = choose_cache (req->af);

    if (!cache || (g_hash_table_size (cache) >= CACHE_SIZE)) {
        return;
    }

    if (res->expiry == -1) {
        now = g_get_monotonic_time ();
        if (now > INT64_MAX - FALLBACK_TTL) {
            return;
        }

        res->expiry = now + FALLBACK_TTL;
    }

    key = g_strdup (req->name);
    val = g_memdup (res, sizeof (*res));

    g_hash_table_insert (cache, key, val);
    g_debug ("Caching %s until %"G_GINT64_FORMAT, req->name, res->expiry);
}

static
const struct nss_tls_res *
query_cache (const int af, const char *name)
{
    gpointer res = NULL;
    GHashTable *cache;

    cache = choose_cache (af);
    if (cache) {
        res = g_hash_table_lookup (cache, name);
        if (res) {
            g_debug ("Found %s in the cache", name);
        }
    }

    return (const struct nss_tls_res *)res;
}

static
gboolean
get_cached_response (struct nss_tls_session *session)
{
    const struct nss_tls_res *res, *cres;

    res = query_cache (session->request.af, session->request.name);
    if (!res) {
        return FALSE;
    }

    if (res->cname[0]) {
        cres = query_cache (session->request.af, res->cname);
        if (cres) {
            memcpy (session->response.addrs,
                    cres->addrs,
                    cres->count * sizeof(cres->addrs[0]));
            session->response.count = cres->count;
            session->response.expiry = cres->expiry;
            strcpy (session->response.cname, res->cname);
            return TRUE;
        }
    }

    memcpy (&session->response, res, sizeof (session->response));
    return TRUE;
}

#endif

static
void
on_response (GObject         *source_object,
             GAsyncResult    *res,
             gpointer        user_data);

static
void
on_sent (GObject         *source_object,
         GAsyncResult    *res,
         gpointer        user_data);

static
gchar *
encode_dns_query (const unsigned char *buf, const gsize len)
{
    gchar *b64;
    size_t i;

    b64 = g_base64_encode (buf, len);

    /* https://tools.ietf.org/html/rfc4648#section-5 */
    for (i = 0; i < strlen (b64); ++i) {
        switch (b64[i]) {
        case '+':
            b64[i] = '-';
            break;

        case '/':
            b64[i] = '_';
            break;

        case '=':
            b64[i] = '\0';
            return b64;
        }
    }

    return b64;
}

static
gboolean
resolve_domain (struct nss_tls_session *session)
{
    static unsigned char buf[512];
    gchar *url, *dns;
#ifdef NSS_TLS_CACHE
    GOutputStream *out;
#endif
    int type, len;
    SoupMessageFlags flags;
    guint id = 0;

#ifdef NSS_TLS_CACHE
    if (get_cached_response (session)) {
        out = g_io_stream_get_output_stream (G_IO_STREAM (session->connection));
        g_output_stream_write_all_async (out,
                                         &session->response,
                                         sizeof (session->response),
                                         G_PRIORITY_DEFAULT,
                                         NULL,
                                         on_sent,
                                         session);
        return TRUE;
    }
#endif

    switch (session->request.af) {
    case AF_INET:
        type = ns_t_a;
        break;

    case AF_INET6:
        type = ns_t_aaaa;
        break;

    default:
        return FALSE;
    }

    len = res_mkquery (QUERY,
                       session->request.name,
                       ns_c_in,
                       type,
                       NULL,
                       0,
                       NULL,
                       buf,
                       sizeof (buf));
    if (len <= 0) {
        return FALSE;
    }

    dns = encode_dns_query (buf, (gsize)len);

#ifdef NSS_TLS_DETERMINISTIC
    if (G_N_ELEMENTS (urls) > 1) {
        id = g_str_hash (session->request.name) % G_N_ELEMENTS (urls);
    }
#else
    id = g_random_int_range (0, G_N_ELEMENTS (urls));
#endif

    if (G_N_ELEMENTS (urls) > 1) {
        g_debug ("Resolving %s (%s) using %s",
                 session->request.name,
                 (session->request.af == AF_INET) ? "IPv4" : "IPv6",
                 urls[id]);
    } else {
        g_debug ("Resolving %s (%s)",
                 session->request.name,
                 (session->request.af == AF_INET) ? "IPv4" : "IPv6");
    }
    url = g_strdup_printf ("https://%s?dns=%s", urls[id], dns);

    session->response.cname[0] = '\0';
    session->type = (gint64)type;

    session->message = soup_message_new ("GET", url);

    flags = soup_message_get_flags (session->message);
    soup_message_set_flags (session->message, flags | SOUP_MESSAGE_IDEMPOTENT);

    soup_message_headers_append (session->message->request_headers,
                                 "Content-Type",
                                 "application/dns-message");
    soup_message_headers_append (session->message->request_headers,
                                 "Accept",
                                 "application/dns-message");

    soup_session_send_async (soup,
                             session->message,
                             NULL,
                             on_response,
                             session);

    g_free (url);
    g_free (dns);

    return TRUE;
}

static
void
resolve_cname (struct nss_tls_session *session)
{
    g_debug ("The canonical name of %s is %s",
             session->request.name,
             session->response.cname);
    strcpy (session->request.name, session->response.cname);

    /*
     * ignore CNAME records for this name; we don't want to be stuck in an
     * infinite loop if the canonical form of A is B, while B has a CNAME record
     * that points back to A
     */
    session->canon = TRUE;

    resolve_domain (session);
}

static
void
on_close (GObject       *source_object,
          GAsyncResult  *res,
          gpointer      user_data)
{
    struct nss_tls_session *session = (struct nss_tls_session *)user_data;

    g_io_stream_close_finish (G_IO_STREAM (source_object), res, NULL);

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

    g_output_stream_write_all_finish (G_OUTPUT_STREAM (source_object),
                                      res,
                                      &out,
                                      NULL);
    stop_session (session);
}

static
void
on_answer (struct nss_tls_session   *session,
           const unsigned char      *dns,
           const gsize              len,
           ns_msg                   *msg,
           const int                rr_id,
           const int                a_type,
           const size_t             addrlen)
{
    ns_rr rr;
    gint64 ttl, now, expiry;
    int type;

    if (ns_parserr (msg, ns_s_an, rr_id, &rr) < 0) {
        g_warning ("Failed to parse a result record for %s",
                   session->request.name);
        return;
    }

    if (ns_rr_class (rr) != ns_c_in)
        return;

    type = ns_rr_type (rr);
    if (type == a_type) {
        if (ns_rr_rdlen (rr) == addrlen) {
            memcpy (&session->response.addrs[session->response.count],
                    ns_rr_rdata (rr),
                    addrlen);
            ++session->response.count;

            ttl = (gint64)ns_rr_ttl (rr);
            if (ttl <= INT64_MAX / 1000000) {
                if (ttl < MIN_TTL)
                    ttl = MIN_TTL;
                ttl *= 1000000;
                now = g_get_monotonic_time ();

                /*
                 * after looking at all answer records, we use the shortest
                 * TTL for all answers
                 */
                if (INT64_MAX - ttl >= now) {
                    expiry = (int64_t)(now + ttl);
                    if ((session->response.expiry == -1) ||
                        (expiry < session->response.expiry)) {
                        session->response.expiry = expiry;
                    }
                }
            }
        }
    }
    else if (!session->canon &&
             (type == ns_t_cname) &&
             !session->response.cname[0] &&
             (ns_rr_rdlen (rr) > 0)) {
        if (dn_expand (dns,
                       dns + len,
                       ns_rr_rdata (rr),
                       session->response.cname,
                       sizeof (session->response.cname)) <= 0) {
            session->response.cname[0] = '\0';
        }
    }
}

static
void
on_body (GObject         *source_object,
         GAsyncResult    *res,
         gpointer        user_data)
{
    ns_msg msg;
    GError *err = NULL;
    struct nss_tls_session *session = (struct nss_tls_session *)user_data;
    GOutputStream *out;
    gsize len;
    size_t addrlen;
    int id, count, a_type;

    if (!g_input_stream_read_all_finish (G_INPUT_STREAM (source_object),
                                         res,
                                         &len,
                                         &err)) {
        goto cleanup;
    }

    switch (session->request.af) {
    case AF_INET:
        a_type = ns_t_a;
        addrlen = sizeof (session->response.addrs[0].in);
        break;

    case AF_INET6:
        a_type = ns_t_aaaa;
        addrlen = sizeof (session->response.addrs[0].in6);
        break;

    default:
        goto cleanup;
    }

    if (ns_initparse (session->dns, (int)len, &msg) < 0) {
        g_warning ("Failed to parse the result for %s", session->request.name);
        goto cleanup;
    }

    count = ns_msg_count(msg, ns_s_an);
    for (id = 0;
         ((id < count) &&
          ((session->response.count < G_N_ELEMENTS (session->response.addrs)) ||
          !session->response.cname[0]));
         ++id) {
        on_answer (session, session->dns, len, &msg, id, a_type, addrlen);
    }

#ifdef NSS_TLS_CACHE
    /* we want to cache addresses or the lack of any addresses */
    add_to_cache (&session->request, &session->response);
#endif

    if (session->response.cname[0] && (session->response.count == 0)) {
        resolve_cname (session);
        return;
    }

    if (session->response.count > 0) {
        out = g_io_stream_get_output_stream (G_IO_STREAM (session->connection));
        g_output_stream_write_all_async (out,
                                         &session->response,
                                         sizeof (session->response),
                                         G_PRIORITY_DEFAULT,
                                         NULL,
                                         on_sent,
                                         session);

        g_debug ("Done resolving %s with %hhu %s result(s)",
                 session->request.name,
                 session->response.count,
                 (session->request.af == AF_INET) ? "IPv4" : "IPv6");

        return;
    }

cleanup:
    if (err) {
        g_error_free (err);
    }

    if (session->response.count == 0) {
        stop_session (session);
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
    GInputStream *in = NULL;

    in = soup_session_send_finish (SOUP_SESSION (source_object),
                                   res,
                                   &err);
    if (!in) {
        if (err) {
            g_warning ("Failed to query %s: %s",
                       session->request.name,
                       err->message);
        }
        else {
            g_warning ("Failed to query %s", session->request.name);
        }
        goto cleanup;
    }

    if (!SOUP_STATUS_IS_SUCCESSFUL (session->message->status_code)) {
        g_warning ("Failed to query %s: HTTP %d",
                   session->request.name,
                   session->message->status_code);
        goto cleanup;
    }

    g_input_stream_read_all_async (in,
                                   session->dns,
                                   sizeof (session->dns),
                                   G_PRIORITY_DEFAULT,
                                   NULL,
                                   on_body,
                                   session);

    g_object_unref (session->message);
    g_object_unref (in);

    return;

cleanup:
    if (err) {
        g_error_free (err);
    }

    if (in) {
        g_object_unref (in);
    }

    g_object_unref (session->message);

    if (session->response.count == 0) {
        stop_session (session);
    }
}

/*
 * we don't want to leak the local domain to the DoH server provider (for
 * example, it may indicate a router model) and we don't want to waste time on
 * this query if it's going to fail anyway
 */
static
gboolean
is_suffixed (const gchar *name)
{
    struct __res_state res;
    gchar *suffix;
    gboolean ret;
    unsigned int i;

    if (res_ninit (&res) < 0) {
        return FALSE;
    }

    for (i = 0; (i < G_N_ELEMENTS (res.dnsrch)) && res.dnsrch[i]; ++i) {
        suffix = g_strconcat (".", res.dnsrch[i], NULL);
        ret = g_str_has_suffix (name, suffix);
        g_free (suffix);
        if (ret) {
            g_debug ("%s is suffixed by a local domain", name);
            return ret;
        }
    }

    return FALSE;
}

/*
 * the DoH server addresses must be resolved by other means, otherwise this
 * results in infinite recursion
 */
static
gboolean
is_server_domain (const gchar *name)
{
    gint i;

    for (i = 0; i < G_N_ELEMENTS (domains); ++i) {
        if (strcmp (name, domains[i]) == 0) {
            g_debug ("%s is a DoH server domain", name);
            return TRUE;
        }
    }

    return FALSE;
}

/* step 2: we received a request from libnss_tls and send a HTTPS request */
static
void
on_request (GObject         *source_object,
            GAsyncResult    *res,
            gpointer        user_data)
{
    GError *err = NULL;
    struct nss_tls_session *session = user_data;
    gsize len;

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

    if (is_suffixed (session->request.name) ||
        is_server_domain (session->request.name)) {
        goto fail;
    }

    if (resolve_domain (session)) {
        return;
    }

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
    session->response.count = 0;
    session->response.expiry = -1;

    /* we assume the domain is not canonical */
    session->canon = FALSE;

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

int main (int argc, char **argv)
{
    static char root_socket[] = NSS_TLS_SOCKET_PATH;
    GMainLoop *loop;
    GSocketService *s;
    GSocketAddress *sa;
    const gchar *runtime_dir;
    struct passwd *user;
    gchar *user_socket = root_socket;
#ifdef NSS_TLS_DEBUG
    static SoupLogger *logger;
#endif
    int mode = 0600;
    uid_t uid;
    gid_t gid;
    gboolean root;
#ifdef NSS_TLS_CACHE
    gint i;
    gboolean cache = TRUE;
#endif

    root = (geteuid () == 0);
    if (root) {
        user = getpwnam (NSS_TLS_USER);
        if (!user) {
            return EXIT_FAILURE;
        }

        uid = user->pw_uid;
        gid = user->pw_gid;

        /*
         * create a directory owned by a non-privileged user, where we put the
         * socket
         */
        if (((mkdir (NSS_TLS_SOCKET_DIR, 0755) < 0) &&
             ((errno != EEXIST) || (chmod (NSS_TLS_SOCKET_DIR, 0755) < 0))) ||
            (chown (NSS_TLS_SOCKET_DIR, uid, gid) < 0) ||
            (setgroups (1, &gid) < 0) ||
            (setgid (gid) < 0) ||
            (setuid (uid) < 0)) {
            return EXIT_FAILURE;
        }

        mode = 0666;
#ifdef NSS_TLS_CACHE
        /*
         * a user should not be allowed to determine whether or not another user
         * resolved a domain, by checking how much time it takes to resolve it
         */
        cache = FALSE;
#endif
    } else {
        runtime_dir = g_get_user_runtime_dir ();
        if (!runtime_dir) {
            return EXIT_FAILURE;
        }

        user_socket = g_build_path ("/",
                                    runtime_dir,
                                    NSS_TLS_SOCKET_NAME,
                                    NULL);
    }

#ifdef NSS_TLS_CACHE
    if (cache) {
        for (i = 0; i < G_N_ELEMENTS (caches); ++i) {
            caches[i] = g_hash_table_new_full (g_str_hash,
                                               g_str_equal,
                                               g_free,
                                               g_free);
        }
    }
#endif

    g_unlink (user_socket);
    sa = g_unix_socket_address_new (user_socket);
    s = g_socket_service_new ();
    loop = g_main_loop_new (NULL, FALSE);

#ifdef NSS_TLS_CACHE
    if (cache) {
        g_timeout_add_seconds (CACHE_CLEANUP_INTERVAL,
                               on_cache_cleanup,
                               NULL);
    }
#endif

    soup = soup_session_new_with_options (SOUP_SESSION_TIMEOUT,
                                          NSS_TLS_TIMEOUT,
                                          SOUP_SESSION_IDLE_TIMEOUT,
                                          NSS_TLS_TIMEOUT,
                                          SOUP_SESSION_USER_AGENT,
                                          NSS_TLS_USER_AGENT,
                                          SOUP_SESSION_MAX_CONNS_PER_HOST,
                                          MAX_CONNS_PER_RESOLVER,
                                          SOUP_SESSION_MAX_CONNS,
                                          MAX_CONNS,
                                          NULL);
#ifdef NSS_TLS_DEBUG
    logger = soup_logger_new (SOUP_LOGGER_LOG_BODY, 128);
    soup_session_add_feature (soup, SOUP_SESSION_FEATURE (logger));
#endif

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
    g_chmod (user_socket , mode);

    g_unix_signal_add (SIGINT, on_term, loop);
    g_unix_signal_add (SIGTERM, on_term, loop);

    g_main_loop_run (loop);

    g_main_loop_unref (loop);
    g_object_unref (s);
    g_unlink (user_socket);
    if (user_socket != root_socket) {
        g_free (user_socket);
    }
    g_object_unref (sa);
#ifdef NSS_TLS_CACHE
    if (cache) {
        for (i = G_N_ELEMENTS (caches) - 1; i >= 0; --i) {
            g_hash_table_unref (caches[i]);
        }
    }
#endif

    return EXIT_SUCCESS;
}
