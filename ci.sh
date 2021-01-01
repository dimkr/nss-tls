#!/bin/sh -xe

# This file is part of nss-tls.
#
# Copyright (C) 2018, 2019, 2020  Dima Krasner
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

meson --prefix=/usr --buildtype=release -Dstrip=true build
ninja -C build install

# make sure automatic DNS to DoH upgrade works
cat << EOF > /etc/resolv.conf
nameserver 1.1.1.1
nameserver 9.9.9.9
EOF
./build/nss-tlsd &
pid=$!
sleep 1
tlslookup google.com

# pick 3 random domains
domains=`echo $DOMAINS | tr ' ' \\\n | shuf | head -n 3`

for d in $domains
do
    tlslookup $d
done

kill -9 $pid
sleep 1

# make sure explicit choice of DoH servers works
echo -n > /etc/resolv.conf
meson configure build -Dresolvers=https://9.9.9.9/dns-query+random,https://dns.google/dns-query+random,https://1.1.1.1/dns-query+random
ninja -C build install

CC=clang meson --prefix=/usr -Db_sanitize=address build-asan
ninja -C build-asan nss-tlsd

ldconfig
echo "8.8.8.8 dns.google" >> /etc/hosts
cp -f /etc/nsswitch.conf /tmp/
sed 's/hosts:.*/hosts: files tls/' -i /etc/nsswitch.conf
./build-asan/nss-tlsd -r | tee /tmp/nss-tlsd.log &
pid=$!
sleep 1

for i in a b c
do
    for d in $domains $IPV6_ONLY_DOMAINS
    do
        valgrind --leak-check=full --track-fds=yes --error-exitcode=1 --errors-for-leak-kinds=all tlslookup $d
    done

    for d in $domains $IPV6_ONLY_DOMAINS
    do
        getent hosts $d
    done
done

# resolving the domain of a DoH server should always fail
tlslookup dns.google && exit 1

# resolving domains suffixed by the local domain should fail too and change of
# the local domain should take effect immediately
echo "search ci" >> /etc/resolv.conf
tlslookup google.com.ci && exit 1

# before 9169a0, the canonical name was an alias (instead of being the name,
# with the non-canonical domain being the alias), so handshakes failed if the
# certificate specified only the non-canonical name
for d in $domains
do
    wget -T 5 -t 2 -O /dev/null https://$d
done

# test against Firefox Nightly
[ -f firefox/firefox ] || wget -O- "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US" | tar -xjf-
./ci.py firefox/firefox $domains

# before 963b0b, 8.8.8.8 responded with 400 if the dns= parameter contained URL
# unsafe characters
[ -n "`grep '^< HTTP/' /tmp/nss-tlsd.log | grep -v 200`" ] && exit 1

sed -i s/^resolvers=.*/resolvers=/ /etc/nss-tls.conf

# if resolving fails, we should try the next NSS module
echo "nameserver 185.228.168.168" > /etc/resolv.conf
kill -9 $pid
sleep 1
./build/nss-tlsd &
pid=$!
sleep 1
getent hosts google.com && exit 1
sed 's/hosts:.*/hosts: tls dns/' -i /etc/nsswitch.conf
getent hosts google.com

# if we have zero DoH servers, we should try the next NSS module
echo > /etc/resolv.conf
kill -9 $pid
sleep 1
./build/nss-tlsd &
pid=$!
sleep 1
echo "nameserver 9.9.9.9" > /etc/resolv.conf
tlslookup google.com && exit 1
getent hosts google.com

# if nss-tlsd is down, we should try the next NSS module
kill -9 $pid
sleep 1
tlslookup google.com && exit 1
getent hosts google.com

exit 0
