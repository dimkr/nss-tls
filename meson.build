# This file is part of nss-tls.
#
# Copyright (C) 2018  Dima Krasner
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

project('nss-tls', 'c', version: '0.1')

add_project_arguments('-DNSS_TLS_RESOLVER="@0@"'.format(get_option('resolver')),
                      '-DNSS_TLS_SOCKET="@0@/run/nss-tls.socket"'.format(get_option('localstatedir')),
                      '-DNSS_TLS_TIMEOUT=@0@'.format(get_option('timeout')),
                      language: 'c')

nss_tlsd = executable('nss-tlsd',
                      'nss-tlsd.c',
                      dependencies: [
                          dependency('glib-2.0'),
                          dependency('gio-2.0'),
                          dependency('gio-unix-2.0'),
                          dependency('json-glib-1.0'),
                          dependency('libsoup-2.4'),
                      ],
                      install: true,
                      install_dir: get_option('sbindir'))

libnss_tls = shared_library('nss_tls', 'nss-tls.c', version: '2', install: true)

cfg = configuration_data()
cfg.set('prefix', get_option('prefix'))
cfg.set('sbindir', get_option('sbindir'))
nss_tlsd_service = configure_file(input: 'nss-tlsd.service.in',
                                  output: 'nss-tlsd.service',
                                  configuration: cfg)
install_data(nss_tlsd_service, install_dir: join_paths(get_option('sysconfdir'), 'systemd', 'system'))

install_man('nss-tlsd.8')
