#!/bin/sh -xe

# This file is part of nss-tls.
#
# Copyright (C) 2018, 2019  Dima Krasner
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

DOMAINS="
    ipv4.google.com
    ipv6.google.com
    google.com
    youtube.com
    facebook.com
    baidu.com
    wikipedia.org
    taobao.com
    amazon.com
    twitter.com
    instagram.com
    reddit.com
    yandex.ru
    netflix.com
    aliexpress.com
    ebay.com
    bing.com
    github.com
"

# at least some Travis and AWS CodeBuild machines don't have an IPv6 route, so
# we only resolve these
IPV6_ONLY_DOMAINS="
    ipv6.google.com
"

CC=gcc-8 meson --prefix=/usr --buildtype=release -Dstrip=true build
ninja -C build install

meson configure build -Dcache=false
ninja -C build

CC=clang-8 meson --prefix=/usr -Dresolvers=9.9.9.9/dns-query,dns.google/dns-query,1.1.1.1/dns-query -Dcache=false -Ddeterministic=false -Db_sanitize=address build-asan
ninja -C build-asan nss-tlsd

ldconfig
echo "8.8.8.8 dns.google" >> /etc/hosts
cp -f /etc/nsswitch.conf /tmp/
sed 's/hosts:.*/hosts: files tls/' -i /etc/nsswitch.conf
G_MESSAGES_DEBUG=all ./build-asan/nss-tlsd | tee /tmp/nss-tlsd.log &
pid=$!
sleep 1

for i in a b c d
do
    for d in $DOMAINS $IPV6_ONLY_DOMAINS
    do
        tlslookup $d
    done

    for d in $DOMAINS $IPV6_ONLY_DOMAINS
    do
        getent hosts $d
    done
done

# before 9169a0, the canonical name was an alias (instead of being the name,
# with the non-canonical domain being the alias), so handshakes failed if the
# certificate specified only the non-canonical name
for d in $DOMAINS
do
    wget -T 5 -t 2 -O /dev/null https://$d
done

kill $pid
sleep 1

# before 963b0b, 8.8.8.8 responded with 400 if the dns= parameter contained URL
# unsafe characters
[ -n "`grep '^< HTTP/' /tmp/nss-tlsd.log | grep -v 200`" ] && exit 1

exit 0
