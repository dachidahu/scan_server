"""
test_csrf.py

Copyright 2012 Andres Riancho

This file is part of w3af, http://w3af.org/ .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
from nose.plugins.attrib import attr

from w3af.plugins.tests.helper import PluginTest, PluginConfig
from w3af.plugins.audit.directory_traversal import directory_traversal 
from w3af.core.data.url.HTTPResponse import HTTPResponse
from w3af.core.data.parsers.doc.url import URL, parse_qs
from w3af.core.data.parsers.utils.form_params import FormParameters
from w3af.core.data.dc.headers import Headers
from w3af.core.data.request.fuzzable_request import FuzzableRequest
from w3af.core.data.dc.urlencoded_form import URLEncodedForm
from w3af.core.data.dc.cookie import Cookie
from w3af.core.data.url.extended_urllib import ExtendedUrllib


class TestDirectoryTraversal(PluginTest):

    target_url = 'http://127.0.0.1:3000/users'

    _run_configs = {
        'cfg': {
            'target': target_url,
            'plugins': {
                'audit': (PluginConfig('directory_traversal'),),
                'crawl': (
                    PluginConfig(
                        'web_spider',
                        ('only_forward', True, PluginConfig.BOOL)),
                )
            }
        }
    }

    def setUp(self):
        super(TestDirectoryTraversal, self).setUp()
        
        self.csrf_plugin = directory_traversal()
        self.uri_opener = ExtendedUrllib()
        self.csrf_plugin.set_url_opener(self.uri_opener)

    @attr('ci_fails')
    def test_found_csrf(self):
        EXPECTED = [
            ('/w3af/audit/csrf/vulnerable/buy.php'),
            ('/w3af/audit/csrf/vulnerable-rnd/buy.php'),
            #@see: https://github.com/andresriancho/w3af/issues/120
            #('/w3af/audit/csrf/vulnerable-token-ignored/buy.php'),
            ('/w3af/audit/csrf/link-vote/vote.php')
        ]
        
        # Run the scan
        cfg = self._run_configs['cfg']
        self._scan(cfg['target'], cfg['plugins'])

        # Assert the general results
        vulns = self.kb.get('directory_traversal', 'directory_traversal')
        print len(vulns)
        self.assertTrue(
            all(['Directory Traversal vulnerability' == v.get_name() for v in vulns]))


