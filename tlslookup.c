/* This file is part of nss-tls.
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
#include <netdb.h>
#include <nss.h>
#include <stdio.h>

#include "nss-tls.h"

extern enum nss_status _nss_tls_gethostbyname2_r(const char *name,
                                                 int af,
                                                 struct hostent *ret,
                                                 char *buf,
                                                 size_t buflen,
                                                 int *errnop,
                                                 int *h_errnop);
int main(int argc, char *argv[])
{
    struct nss_tls_data data;
    struct hostent ent;
    char buf[INET6_ADDRSTRLEN];
    int err, h_err, i, afs[] = {AF_INET, AF_INET6};
    uint16_t total = 0;
    uint8_t j;

    if (argc != 2) {
        fprintf(stderr,
                "Usage: tlslookup HOST\n"
                "Resolve the internet address of HOST.\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < sizeof(afs) / sizeof(afs[0]); ++i) {
        switch (_nss_tls_gethostbyname2_r(argv[1],
                                          afs[i],
                                          &ent,
                                          (char *)&data,
                                          sizeof(data),
                                          &err,
                                          &h_err)) {
        case NSS_STATUS_SUCCESS:
            break;

        case NSS_STATUS_NOTFOUND:
            continue;

        default:
            return EXIT_FAILURE;
        }

        for (j = 0; j < data.res.count; ++j) {
            if (!inet_ntop(afs[i], &data.res.addrs[j], buf, sizeof(buf)) ||
                (puts(buf) == EOF))
                return EXIT_FAILURE;
        }

        total += data.res.count;
    }

    if (total == 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
