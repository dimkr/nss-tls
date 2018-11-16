#!/usr/bin/python3
#
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

from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.options import Options
import os

SITES = ("youtube.com",)

opts = Options()
if os.getenv("CI"):
    opts.add_argument("-headless")

for binary in [FirefoxBinary("/usr/bin/firefox")] + [FirefoxBinary("%s/firefox/firefox" % x) for x in os.listdir('.') if x.startswith("firefox-") and os.path.isdir(x)]:
    with webdriver.Firefox(firefox_binary=binary, firefox_options=opts) as ff:
        for i in SITES:
            for j in ("http", "https"):
                url = "%s://%s/" % (j, i)
                ff.get(url)
                assert i in ff.current_url
