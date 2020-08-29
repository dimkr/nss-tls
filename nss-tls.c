/*
 * This file is part of nss-tls.
 *
 * Copyright (C) 2018, 2019, 2020  Dima Krasner
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
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <pthread.h>
#include <stdint.h>

#include "nss-tls.h"

static void cleanup(void *arg)
{
    close((int)(intptr_t)arg);
}

enum nss_status _nss_tls_gethostbyname2_r(const char *name,
                                          int af,
                                          struct hostent *ret,
                                          char *buf,
                                          size_t buflen,
                                          int *errnop,
                                          int *h_errnop)
{
    struct sockaddr_un sun = {.sun_family = AF_UNIX};
    struct timeval tv = {.tv_sec = NSS_TLS_TIMEOUT / 2, .tv_usec = 0};
    struct nss_tls_data *data = (struct nss_tls_data *)buf;
    const char *dir;
    ssize_t out, total;
    size_t len;
    int s, i, state;
    enum nss_status status = NSS_STATUS_TRYAGAIN;
    uint8_t count;

    if (buflen < sizeof(*data)) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    *errnop = ENOENT;
    *h_errnop = NETDB_SUCCESS;

    const char *const socketpath = getenv("NSS_TLS_SOCKET");

    if (!socketpath || getuid() != geteuid()) {
        if (geteuid() == 0)
            strcpy(sun.sun_path, NSS_TLS_SOCKET_PATH);
        else {
            dir = getenv("XDG_RUNTIME_DIR");
            if (dir) {
                len = strlen(dir);
                if (len > sizeof(sun.sun_path) - sizeof("/"NSS_TLS_SOCKET_NAME))
                    return NSS_STATUS_TRYAGAIN;

                memcpy(sun.sun_path, dir, len);
                sun.sun_path[len] = '/';
                ++len;
                strncpy(sun.sun_path + len,
                        NSS_TLS_SOCKET_NAME,
                        sizeof(sun.sun_path) - len);
                sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';
             } else
                strcpy(sun.sun_path, NSS_TLS_SOCKET_PATH);
        }
    } else {
        len = strlen (socketpath);
        if (len >= sizeof(sun.sun_path)) return EXIT_FAILURE;
        memcpy (sun.sun_path, socketpath, len + 1);
    }

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

    s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
        if (state != PTHREAD_CANCEL_DISABLE)
            pthread_setcancelstate(state, NULL);
        *errnop = EAGAIN;
        return NSS_STATUS_TRYAGAIN;
    }

    pthread_cleanup_push(cleanup, (void *)(intptr_t)s);

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    if ((setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) ||
        (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0))
        goto pop;

    if (connect(s, (const struct sockaddr *)&sun, sizeof(sun)) < 0) {
        if (errno != ENOENT)
            goto pop;

        strcpy(sun.sun_path, NSS_TLS_SOCKET_PATH);
        if (connect(s, (const struct sockaddr *)&sun, sizeof(sun)) < 0)
            goto pop;
    }

    data->req.af = af;
    strncpy(data->req.name, name, sizeof(data->req.name));
    data->req.name[sizeof(data->req.name) - 1] = '\0';
    for (total = 0; total < sizeof(data->req); total += out) {
        out = send(s,
                   (unsigned char *)&data->req + total,
                   sizeof(data->req) - total,
                   MSG_NOSIGNAL);
        if (out <= 0)
            goto pop;
    }

    for (total = 0; total < sizeof(data->res); total += out) {
        out = recv(s,
                   (unsigned char *)&data->res + total,
                   sizeof(data->res) - total,
                   0);
        if (out < 0)
            goto pop;
        if (out == 0)
            break;
    }

    if (total == 0) {
        status = NSS_STATUS_NOTFOUND;
        goto pop;
    }

    if (total != sizeof(data->res))
        goto pop;

    if (data->res.cname[0]) {
        ret->h_name = data->res.cname;
        data->aliases[0] = data->req.name;
        data->aliases[1] = NULL;
    } else {
        ret->h_name = data->req.name;
        data->aliases[0] = NULL;
    }
    ret->h_aliases = data->aliases;
    ret->h_addrtype = af;
    data->addrs[0] = NULL;
    ret->h_addr_list = data->addrs;

    count = data->res.count;
    if (count == 0) {
        *h_errnop = HOST_NOT_FOUND;
        status = NSS_STATUS_NOTFOUND;
        goto pop;
    }
    if (count > NSS_TLS_ADDRS_MAX)
        count = NSS_TLS_ADDRS_MAX;

    switch (af) {
    case AF_INET:
        ret->h_length = sizeof(struct in_addr);
        break;

    case AF_INET6:
        ret->h_length = sizeof(struct in6_addr);
        break;

    default:
        status = NSS_STATUS_NOTFOUND;
        goto pop;
    }

    for (i = 0; i < count; ++i)
        data->addrs[i] = (char *)&data->res.addrs[i];
    data->addrs[i] = NULL;

    *errnop = 0;
    status = NSS_STATUS_SUCCESS;

pop:
    pthread_cleanup_pop(1);
    return status;
}
