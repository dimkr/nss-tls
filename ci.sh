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

CC=gcc-8 meson --prefix=/usr --buildtype=release -Dstrip=true build
ninja -C build install

CC=clang-8 meson --prefix=/usr -Dresolver=1.1.1.1/dns-query -Db_sanitize=address build-asan
exit 1
ninja -C build-asan nss-tlsd

ldconfig
cp -f /etc/nsswitch.conf /tmp/
sed 's/hosts:.*/hosts: files tls/' -i /etc/nsswitch.conf
G_MESSAGES_DEBUG=all ./build-asan/nss-tlsd &
pid=$!
sleep 1

tlslookup ipv4.google.com
tlslookup ipv6.google.com
tlslookup google.com

getent hosts ipv4.google.com
getent hosts ipv6.google.com
getent hosts google.com

kill $pid
sleep 1
