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

project('nss-tls', 'c', version: '1.0', license : ['LGPL2.1+'])

resolvers = get_option('resolvers')
resolver_urls = []
resolver_domains = []
foreach resolver_url: resolvers.split(',')
    resolver_domain = resolver_url.split('/')[0]
    resolver_domains += ['"@0@"'.format(resolver_domain)]
    resolver_urls += ['"@0@"'.format(resolver_url)]
endforeach
resolver_urls = ','.join(resolver_urls)
resolver_domains = ','.join(resolver_domains)

nss_tls_socket_name = 'nss-tlsd.sock'
nss_tls_socket_dir = '@0@/run/nss-tls'.format(get_option('localstatedir'))
nss_tls_socket_path = '@0@/@1@'.format(nss_tls_socket_dir, nss_tls_socket_name)
nss_tls_user = get_option('user')
nss_tls_group = get_option('group')
nss_tls_user_agent = '@0@/@1@'.format(meson.project_name(),
                                      meson.project_version())
nss_tlsd_path = join_paths(get_option('prefix'),
                           get_option('sbindir'),
                           'nss-tlsd')

add_project_arguments(
    '-DNSS_TLS_RESOLVER_URLS=@0@'.format(resolver_urls),
    '-DNSS_TLS_RESOLVER_DOMAINS=@0@'.format(resolver_domains),
    '-DNSS_TLS_SOCKET_NAME="@0@"'.format(nss_tls_socket_name),
    '-DNSS_TLS_SOCKET_DIR="@0@"'.format(nss_tls_socket_dir),
    '-DNSS_TLS_SOCKET_PATH="@0@"'.format(nss_tls_socket_path),
    '-DNSS_TLS_TIMEOUT=@0@'.format(get_option('timeout')),
    '-DNSS_TLS_USER_AGENT="@0@"'.format(nss_tls_user_agent),
    '-DNSS_TLS_USER="@0@"'.format(nss_tls_user),
    '-DNSS_TLS_GROUP="@0@"'.format(nss_tls_group),
    language: 'c'
)

if get_option('cache')
    add_project_arguments('-DNSS_TLS_CACHE', language: 'c')
endif

if get_option('buildtype').startswith('debug')
    add_project_arguments('-DNSS_TLS_DEBUG', language: 'c')
endif

nss_tlsd = executable('nss-tlsd',
                      'nss-tlsd.c',
                      dependencies: [
                          meson.get_compiler('c').find_library('resolv'),
                          dependency('glib-2.0', version: '>=2.44'),
                          dependency('gio-2.0'),
                          dependency('gio-unix-2.0'),
                          dependency('libsoup-2.4'),
                      ],
                      install: true,
                      install_dir: get_option('sbindir'))

libnss_tls = shared_library('nss_tls', 'nss-tls.c', version: '2', install: true)

tlslookup = executable('tlslookup',
                       'tlslookup.c',
                       link_with: libnss_tls,
                       install: true)

systemd = dependency('systemd', required: false)
if systemd.found()
    cfg = configuration_data()
    cfg.set('nss_tlsd_path', nss_tlsd_path)

    nss_tlsd_service = configure_file(input: 'nss-tlsd.service.in',
                                      output: 'nss-tlsd.service',
                                      configuration: cfg)
    systemd_unit_dir = systemd.get_pkgconfig_variable('systemdsystemunitdir')
    install_data(nss_tlsd_service, install_dir: systemd_unit_dir)

    nss_tlsd_user_service = configure_file(input: 'nss-tlsd-user.service.in',
                                           output: 'nss-tlsd-user.service',
                                           configuration: cfg)
    systemd_user_unit_dir = systemd.get_pkgconfig_variable('systemduserunitdir')
    install_data(nss_tlsd_user_service,
                 install_dir: systemd_user_unit_dir,
                 rename: 'nss-tlsd.service')
endif

install_man('nss-tlsd.8')
