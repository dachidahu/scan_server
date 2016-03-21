"""
generic.py

Copyright 2007 Andres Riancho

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

import w3af.core.data.kb.knowledge_base as kb
import w3af.core.data.constants.severity as severity

from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.fuzzer.fuzzer import create_mutants
from w3af.core.data.fuzzer.utils import rand_number, rand_alnum
from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.db.disk_list import DiskList

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.controllers.misc.fuzzy_string_cmp import relative_distance


class generic(AuditPlugin):
    """
    Find all kind of bugs without using a fixed database of errors.
    :author: Andres Riancho (andres.riancho@gmail.com)
    """

    ERROR_STRINGS = ['d\'kc"z\'gj\'\"**5*(((;-*`)', '']

    def __init__(self):
        AuditPlugin.__init__(self)

        #   Internal variables
        self._potential_vulns = DiskList(table_prefix='generic')

        #   User configured variables
        self._diff_ratio = 0.30

    def audit(self, freq, orig_response):
        """
        Find all kind of bugs without using a fixed database of errors.

        :param freq: A FuzzableRequest
        """
        # First, get the original response and create the mutants
        mutants = create_mutants(freq, ['', ], orig_resp=orig_response)

        for m in mutants:

            # First I check that the current modified parameter in the mutant
            # doesn't have an already reported vulnerability. I don't want to
            # report vulnerabilities more than once.
            if (m.get_url(), m.get_token_name()) in self._potential_vulns:
                continue

            # Now, we request the limit (something that doesn't exist)
            # If http://localhost/a.php?b=1
            #   * Then I should request b=12938795 (random number)
            #
            # If http://localhost/a.php?b=abc
            #   * Then I should request b=hnv98yks (random alnum)
            limit_response = self._get_limit_response(m)

            # Now I request something that could generate an error
            # If http://localhost/a.php?b=1
            #   * Then I should request b=d'kcz'gj'"**5*(((*)
            #
            # If http://localhost/a.php?b=abc
            #   * Then I should request b=d'kcz'gj'"**5*(((*)
            #
            # I also try to trigger errors by sending empty strings
            #     If http://localhost/a.php?b=1 ; then I should request b=
            #     If http://localhost/a.php?b=abc ; then I should request b=
            for error_string in self.ERROR_STRINGS:

                m.set_token_value(error_string)
                error_response = self._uri_opener.send_mutant(m)

                # Now I compare responses
                self._analyze_responses(orig_response, limit_response,
                                        error_response, m)

    def _analyze_responses(self, orig_resp, limit_response, error_response, mutant):
        """
        Analyze responses; if error_response doesn't look like orig_resp nor
        limit_response, then we have a vuln.

        :return: None
        """
        original_to_error = relative_distance(orig_resp.get_body(),
                                              error_response.get_body())
        limit_to_error = relative_distance(limit_response.get_body(),
                                           error_response.get_body())
        original_to_limit = relative_distance(limit_response.get_body(),
                                              orig_resp.get_body())

        ratio = self._diff_ratio + (1 - original_to_limit)

        if original_to_error < ratio and limit_to_error < ratio:
            # Maybe the limit I requested wasn't really a non-existent one
            # (and the error page really found the limit),
            # let's request a new limit (one that hopefully doesn't exist)
            # in order to remove some false positives
            limit_response2 = self._get_limit_response(mutant)

            id_list = [orig_resp.id, limit_response.id, error_response.id]

            if relative_distance(limit_response2.get_body(),
                                 limit_response.get_body()) > 1 - self._diff_ratio:
                # The two limits are "equal"; It's safe to suppose that we have
                # found the limit here and that the error string really produced
                # an error
                self._potential_vulns.append((mutant.get_url(),
                                              mutant.get_token_name(),
                                              mutant, id_list))

    def _get_limit_response(self, mutant):
        """
        We request the limit (something that doesn't exist)
            - If http://localhost/a.php?b=1
                then I should request b=12938795 (random number)
            - If http://localhost/a.php?b=abc
                then I should request b=hnv98yks (random alnum)

        :return: The limit response object
        """
        mutant_copy = mutant.copy()

        is_digit = mutant.get_token_original_value().isdigit()
        value = rand_number(length=8) if is_digit else rand_alnum(length=8)
        mutant_copy.set_token_value(value)
        limit_response = self._uri_opener.send_mutant(mutant_copy)

        return limit_response

    def end(self):
        """
        This method is called when the plugin wont be used anymore.
        """
        all_findings = kb.kb.get_all_findings()

        for url, variable, mutant, id_list in self._potential_vulns:
            for info in all_findings:
                if info.get_token_name() == variable and info.get_url() == url:
                    break
            else:
                desc = 'An unhandled error, which could potentially translate' \
                       ' to a vulnerability, was found at: %s'
                desc = desc % mutant.found_at()
                
                v = Vuln.from_mutant('Unhandled error in web application', desc,
                                     severity.LOW, id_list, self.get_name(),
                                     mutant)
        
                self.kb_append_uniq(self, 'generic', v)
        
        self._potential_vulns.cleanup()        
                
    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        ol = OptionList()

        d = 'If two strings have a diff ratio less than diff_ratio, then they'\
            '  are really different.'
        o = opt_factory('diff_ratio', self._diff_ratio, d, 'float')
        ol.add(o)

        return ol

    def set_options(self, options_list):
        """
        This method sets all the options that are configured using the user
        interface generated by the framework using the result of get_options().

        :param options_list: A dictionary with the options for the plugin.
        :return: No value is returned.
        """
        self._diff_ratio = options_list['diff_ratio'].get_value()

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return """
        This plugin identifies unhandled Web application exceptions by sending
        specially crafted strings to each input.
        """
