```
                     _   _
 _ __  ___ ___      | |_| |___
| '_ \/ __/ __|_____| __| / __|
| | | \__ \__ \_____| |_| \__ \
|_| |_|___/___/      \__|_|___/
```

![Build Status](https://codebuild.us-east-1.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiUzM4dGlsK2dPMmdoRkNQcjRjSU1JVmJENHNCTFFHVzVXSUQ0eWw2ajhYZVU3d0hhb2s0d0pzdzNNZUxSenc2Y1J3VmNyak9Udy91cUVsazlOR1h4WWJZPSIsIml2UGFyYW1ldGVyU3BlYyI6IjdFTWxobnVDRVVLbWNkUEYiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)

__This is the deprecated 0.x branch of nss-tls, which uses RFC 8484 incompliant, JSON-based resolving. Unless you have a good reason to use this version, use a later version.__

## Motivation

Unlike most web browser traffic, which is encrypted thanks to HTTPS, the resolving of domain names to internet addresses still happens through DNS, an old, unencrypted protocol. This benefits analytics companies, advertisers, internet providers and attackers, but not the end-user, who seeks online privacy and security.

## Overview

nss-tls is an alternative, encrypted name resolving library for [Linux](http://www.kernel.org/) distributions with [glibc](https://www.gnu.org/software/libc/), which uses [DNS-over-HTTPS (DoH)](https://tools.ietf.org/html/rfc8484).

The glibc name resolver can be configured through nsswitch.conf(5) to use nss-tls instead of the DNS resolver, or fall back to DNS when nss-tls fails.

This way, all applications that use the standard resolver API (getaddrinfo(), gethostbyname(), etc'), are transparently migrated from DNS to encrypted means of name resolving, with zero application-side changes and minimal resource consumption footprint. However, nss-tls does not deal with applications that use their own, built-in DNS resolver.

## Architecture

nss-tls consists of three parts:

* nss-tlsd runs in the background and receives name resolving requests over a Unix socket.
* libnss_tls.so is a tiny client library which delegates the resolving work to nss-tlsd through the Unix socket and passes the results back to the application. This way, applications that take advantage of nss-tls are not affected by the complexity and the resource consumption of the libraries it depends on, or the constraints they impose on applications that use them.
* tlslookup is equivalent to nslookup(1), but uses libnss_tls.so instead of DNS.

## Security and Privacy

An unprivileged user can start a private, unprivileged instance of nss-tlsd and libnss-tls.so will automatically use that one, instead of the system-wide instance of nss-tlsd. Each user's nss-tls instance holds its own cache of lookup results, to speed up resolving. Because the cache is not shared with other users, it remains "hot" even if other users resolve many names.

Users who don't have such a private instance will continue to use the system-wide instance, which does not perform caching, to prevent a user from extracting the browsing history of another user, using timing-based methods. In addition, nss-tlsd drops its privileges to greatly reduce its attack surface.

Also, nss-tls is capable of using multiple DoH servers, with a deterministic algorithm that chooses which server to use to resolve a domain. This way, no DoH server can track the user's entire browsing history.

## Dependencies

nss-tls depends on:
* [glibc](https://www.gnu.org/software/libc/)
* [GLib](https://wiki.gnome.org/Projects/GLib)
* [libsoup](https://wiki.gnome.org/Projects/libsoup)
* [JSON-GLib](https://wiki.gnome.org/Projects/JsonGlib)

If [systemd](https://www.freedesktop.org/wiki/Software/systemd/) is present, the installation of nss-tls includes unit files for nss-tlsd.

However, nss-tlsd does not depend on [systemd](https://www.freedesktop.org/wiki/Software/systemd/). When [systemd](https://www.freedesktop.org/wiki/Software/systemd/) is not present, other means of running a nss-tlsd instance for each user (e.g. xinitrc) and root (e.g. an init script) should be used.

nss-tls uses [Meson](http://mesonbuild.com/) as its build system.

On [Debian](http://www.debian.org/) and derivatives, these dependencies can be obtained using:

    apt install libglib2.0-dev libsoup2.4-dev libjson-glib-dev ninja-build python3-pip
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

By default, nss-tls performs all name lookup through [cloudflare-dns.com/dns-query](https://developers.cloudflare.com/1.1.1.1/dns-over-https/).

To use a different DoH server, use the "resolvers" build option:

    meson configure -Dresolvers=dns9.quad9.net:5053/dns-query

## Using Multiple DoH Servers

It is also possible to use multiple DoH servers:

    meson configure -Dresolvers=cloudflare-dns.com/dns-query,dns9.quad9.net:5053/dns-query

When nss-tls is configured like this, it pseudo-randomly chooses one of the servers, for each name lookup. The pseudo-random choice of the server is deterministic: if the same domain is resolved twice (e.g. for its IPv4 and IPv6 addresses, respectively), nss-tlsd will use the same DoH server for both queries. If nss-tlsd is restarted, it will keep using the same DoH server to resolve that domain. This contributes to privacy, since every DoH server sees only a portion of the user's browsing history.

Previously, nss-tls was limited to a single server, specified using the now deprecated "resolver" build option.

## DoH Without Fallback to DNS

To use nss-tls for name resolving, without falling back to DNS if resolving fails, build nss-tls with DoH servers specified using their addresses, e.g.:

    meson configure -Dresolvers=1.1.1.1/dns-query,9.9.9.9:5053/dns-query

This way, nss-tls will not depend on other means of name resolving to resolve a DoH server address.

Then, remove all DNS resolvers from the "hosts" entry in /etc/nsswitch.conf and keep "tls".

## Performance

DNS over HTTPS is much slower than DNS. Therefore, by default, each user's nss-tls instance maintains an internal cache of lookup results.

However, one may wish to use a system-wide cache; nscd(8) can do that.

To disable the internal cache, use the "cache" build option:

    meson configure -Dcache=false

To enable system-wide DNS cache on [Debian](http://www.debian.org/) and derivatives:

    apt install unscd

Set "enable-cache" for "hosts" to "yes" in /etc/nscd.conf. Then:

    systemctl enable unscd
    systemctl start unscd

## Legal Information

nss-tls is free and unencumbered software released under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option) any later version license.

nss-tls is not affiliated with 1.1.1.1, [Cloudflare](https://www.cloudflare.com/) or [Quad9](https://www.quad9.net/).

The ASCII art logo at the top was made using [FIGlet](http://www.figlet.org/).
