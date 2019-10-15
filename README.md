```
                     _   _
 _ __  ___ ___      | |_| |___
| '_ \/ __/ __|_____| __| / __|
| | | \__ \__ \_____| |_| \__ \
|_| |_|___/___/      \__|_|___/
```

[![Build Status](https://travis-ci.org/dimkr/nss-tls.svg?branch=master)](https://travis-ci.org/dimkr/nss-tls)

## Motivation

Unlike most web browser traffic, which is encrypted thanks to HTTPS, the resolving of domain names to internet addresses still happens through DNS, an old, unencrypted protocol. This benefits analytics companies, advertisers, internet providers and attackers, but not the end-user, who seeks online privacy and security.

## Overview

nss-tls is an alternative, encrypted name resolving library for [Linux](http://www.kernel.org/) distributions with [glibc](https://www.gnu.org/software/libc/), which uses [DNS-over-HTTPS (DoH)](https://tools.ietf.org/html/rfc8484).

The glibc name resolver can be configured through nsswitch.conf(5) to use nss-tls instead of the DNS resolver, or fall back to DNS when nss-tls fails.

This way, all applications that use the standard resolver API (getaddrinfo(), gethostbyname(), etc'), are transparently migrated from DNS to encrypted means of name resolving, with zero application-side changes and minimal resource consumption footprint. However, nss-tls does not deal with applications that use their own, built-in DNS resolver.

## Architecture

nss-tls consists of three parts:

* nss-tlsd runs in the background and receives name resolving requests over a Unix socket.
* libnss_tls.so is a tiny client library, which delegates the resolving work to nss-tlsd through the Unix socket and passes the results back to the application, without dependencies other than libc. This way, applications that resolve through nss-tls are not affected by the complexity and resource consumption of runtime libraries (e.g. libstdc++) and dependency libraries, or the constraints they impose on applications that load them (like signal or thread safety issues).
* tlslookup is equivalent to nslookup(1), but uses libnss_tls.so instead of DNS.

## Security and Privacy

An unprivileged user can start a private, unprivileged instance of nss-tlsd and libnss-tls.so will automatically use that one, instead of the system-wide instance of nss-tlsd. Each user's nss-tls instance holds its own cache of lookup results, to speed up resolving. Because the cache is not shared with other users, it remains "hot" even if other users resolve many names.

Users who don't have such a private instance will continue to use the system-wide instance, which does not perform caching, to prevent a user from extracting the browsing history of another user, using timing-based methods. In addition, nss-tlsd drops its privileges to greatly reduce its attack surface.

Also, nss-tls is capable of using multiple DoH servers, with a deterministic algorithm that chooses which server to use to resolve a domain. This way, no DoH server can track the user's entire browsing history.

To avoid bloat, duplicate effort and potential remotely-exploitable vulnerabilities, nss-tls use the libc API for building DNS queries and parsing responses, instead of implementing its own parser.

## Dependencies

nss-tls depends on:
* [glibc](https://www.gnu.org/software/libc/)
* [GLib](https://wiki.gnome.org/Projects/GLib)
* [libsoup](https://wiki.gnome.org/Projects/libsoup)

If [systemd](https://www.freedesktop.org/wiki/Software/systemd/) is present, the installation of nss-tls includes unit files for nss-tlsd.

However, nss-tlsd does not depend on [systemd](https://www.freedesktop.org/wiki/Software/systemd/). When [systemd](https://www.freedesktop.org/wiki/Software/systemd/) is not present, other means of running a nss-tlsd instance for each user (e.g. xinitrc) and root (e.g. an init script) should be used.

nss-tls uses [Meson](http://mesonbuild.com/) as its build system.

On [Debian](http://www.debian.org/) and derivatives, these dependencies can be obtained using:

    apt install libglib2.0-dev libsoup2.4-dev ninja-build python3-pip
    pip3 install meson

## Usage

Assuming your system runs [systemd](https://www.freedesktop.org/wiki/Software/systemd/):

    meson --prefix=/usr --buildtype=release -Dstrip=true build
    ninja -C build install
    systemctl daemon-reload
    systemctl enable nss-tlsd
    systemctl start nss-tlsd
    systemctl --user --global enable nss-tlsd
    systemctl --user start nss-tlsd
    ldconfig

Then, add "tls" to the "hosts" entry in /etc/nsswitch.conf, before "dns" or anything else that contains "dns".

This will enable a system nss-tlsd instance for all non-interactive processes (which runs as an unprivileged user) and a private instance of nss-tlsd for each user. Name resolving will happen through nss-tls and DNS will be attempted only if nss-tls fails.

## Choosing a DoH Server

By default, nss-tls performs all name lookup through [Quad9](https://www.quad9.net/doh-quad9-dns-servers/).

To use a different DoH server, use the "resolvers" build option:

    meson configure -Dresolvers=https://cloudflare-dns.com/dns-query

## Using Multiple DoH Servers

It is also possible to use multiple DoH servers:

    meson configure -Dresolvers=https://dns9.quad9.net/dns-query,https://cloudflare-dns.com/dns-query

When nss-tls is configured like this, it pseudo-randomly chooses one of the servers, for each name lookup. The pseudo-random choice of the server is deterministic: if the same domain is resolved twice (e.g. for its IPv4 and IPv6 addresses, respectively), nss-tlsd will use the same DoH server for both queries. If nss-tlsd is restarted, it will keep using the same DoH server to resolve that domain. This contributes to privacy, since every DoH server sees only a portion of the user's browsing history.

## Choosing the HTTP Method

A standard DoH server should support both GET and POST requests. By default, nss-tlsd sends POST requests, beause they are faster to craft and tend to be smaller.

However, one might wish to use GET requests if this makes a specific DoH server respond faster (for example, if the server does not cache responses to POST requests). This can be done by adding "+get" after the server URL:

    meson configure -Dresolvers=https://dns.google/dns-query+get

## DoH Without Fallback to DNS

If the DoH servers used by nss-tls are specified using their domain names, nss-tls needs a way to resolve the address of each DoH server and it cannot resolve it through itself.

To build nss-tls without dependency on other resolving methods (like DNS), specify the DoH servers using their addresses, e.g.:

    meson configure -Dresolvers=https://9.9.9.9/dns-query,https://1.1.1.1/dns-query

Alternatively, the DoH server addresses can be hardcoded using /etc/hosts, e.g:

    echo "8.8.8.8 dns.google" >> /etc/hosts
    meson configure -Dresolvers=https://dns.google/dns-query

To disable DNS and use nss-tls exclusively, remove all DNS resolvers from the "hosts" entry in /etc/nsswitch.conf (but keep "tls").

## Performance

On paper, DNS over HTTPS is much slower than DNS, due to the overhead of TCP and TLS.

Therefore, each nss-tls instance keeps established HTTPS connections open and reuses them. Also, by default, each user's nss-tls instance maintains an internal cache of lookup results. In this cache, IPv4 and IPv6 addresses are stored in separate hash tables, to make the cache faster to iterate over.

Therefore, in reality, DNS over HTTPS using nss-tls may be much faster than DNS.

To disable the internal cache, use the "cache" build option:

    meson configure -Dcache=false

One may wish to use a system-wide cache that also covers DNS, instead of the internal cache of nss-tls; nscd(8) can do that. To enable system-wide cache on [Debian](http://www.debian.org/) and derivatives:

    apt install unscd

Then, set "enable-cache" for "hosts" to "yes" in /etc/nscd.conf. Then:

    systemctl enable unscd
    systemctl start unscd

## Legal Information

nss-tls is free and unencumbered software released under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option) any later version license.

nss-tls is not affiliated with [Quad9](https://www.quad9.net/), [Cloudflare](https://www.cloudflare.com/) or [Google](https://www.google.com/).

The ASCII art logo at the top was made using [FIGlet](http://www.figlet.org/).
