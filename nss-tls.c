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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <nss.h>

#include "nss-tls.h"

enum nss_status _nss_tls_gethostbyname2_r(const char *name,
                                          int af,
                                          struct hostent *ret,
                                          char *buf,
                                          size_t buflen,
                                          int *errnop,
                                          int *h_errnop)
{
    struct sockaddr_un sun = {.sun_family = AF_UNIX};
    struct nss_tls_req req;
    struct nss_tls_res res;
    char *addrs[] = {(char *)&res.addr, NULL};
    char *aliases[] = {NULL};
    int s;

    *errnop = ENOENT;

    /* must be resolved by other means, otherwise this results in infinite
     * recursion */
    if (strcmp(name, NSS_TLS_RESOLVER) == 0)
        return NSS_STATUS_NOTFOUND;

    s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
        *errnop = EAGAIN;
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(sun.sun_path, NSS_TLS_SOCKET);
    if (connect(s, (const struct sockaddr *)&sun, sizeof(sun)) < 0) {
        close(s);
        return NSS_STATUS_TRYAGAIN;
    }

    req.af = af;
    strncpy(req.name, name, sizeof(req.name));
    req.name[sizeof(req.name) - 1] = '\0';
    if (send(s, &req, sizeof(req), 0) != sizeof(req)) {
        close(s);
        return NSS_STATUS_UNAVAIL;
    }

    if (recv(s, &res, sizeof(res), 0) != sizeof(res)) {
        close(s);
        return NSS_STATUS_NOTFOUND;
    }

    switch (af) {
    case AF_INET:
        ret->h_length = sizeof(struct in_addr);
        break;

    case AF_INET6:
        ret->h_length = sizeof(struct in6_addr);
        break;

    default:
        return NSS_STATUS_NOTFOUND;
    }

    ret->h_name = req.name;
    ret->h_aliases = aliases;
    ret->h_addrtype = af;
    ret->h_addr_list = addrs;

    return NSS_STATUS_SUCCESS;
}
