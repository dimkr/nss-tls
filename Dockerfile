# This file is part of nss-tls.
#
# Copyright (C) 2018, 2019, 2020, 2021  Dima Krasner
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

FROM ghcr.io/dimkr/containers/c-dev:clang

RUN apt-get -qq update && apt-get -y --no-install-recommends install pkg-config libglib2.0-dev libsoup2.4-dev systemd firefox && apt-get autoremove --purge && apt-get autoclean
RUN pip3 install selenium
RUN wget -O- https://github.com/mozilla/geckodriver/releases/download/v0.26.0/geckodriver-v0.26.0-linux64.tar.gz | tar -xzf- -C /usr/local/bin
