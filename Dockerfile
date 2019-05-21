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

FROM dimkr/c-dev

RUN apt-get -qq update && apt-get -y --no-install-recommends install pkg-config libglib2.0-dev libsoup2.4-dev libjson-glib-dev systemd firefox && apt-get autoremove --purge && apt-get autoclean
