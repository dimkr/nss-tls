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

#include <inttypes.h>
#include <netinet/in.h>

#define NSS_TLS_ADDRS_MAX 16

struct nss_tls_req {
    int af;
    char name[256];
} __attribute__((packed));

struct nss_tls_res {
    uint8_t count;
    union {
        struct in_addr in;
        struct in6_addr in6;
    } addrs[NSS_TLS_ADDRS_MAX];
} __attribute__((packed));
