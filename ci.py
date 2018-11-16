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
import unittest

SITES = ("youtube.com",)

opts = Options()
if os.getenv("CI"):
    opts.add_argument("-headless")

class FirefoxTest(unittest.TestCase):
    path = "/usr/bin/firefox"

    def setUp(self):
        self.driver = webdriver.Firefox(firefox_binary=FirefoxBinary(self.path), options=opts)

    def tearDown(self):
        self.driver.quit()

    def _test_proto(self, proto):
        for s in SITES:
            url = "%s://%s" % (proto, s)
            self.driver.get(url)
            assert s in self.driver.current_url

    def test_http(self):
        self._test_proto("http")

    def test_https(self):
        self._test_proto("https")

if __name__ == "__main__":
    unittest.main()
