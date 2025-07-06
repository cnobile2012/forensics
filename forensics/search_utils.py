# -*- coding: utf-8 -*-
#
# forensics/search_utils.py
#
# by: Carl J. Nobile
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

import re
import os
import stat
import time
import hashlib
import csv
from collections import OrderedDict


__version__ = '2.0.0'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])



class Keywords(object):
    """
    """
    _REGEX_SPLIT = re.compile(r"[,|\r\n\t]+")

    def __init__(self, log):
        self._log = log

    def fromFile(self, filepath):
        result = u''

        try:
            with open(filepath, 'rb') as f:
                result = f.read()
        except IOError as e:
            self._log.critical("Could not open or read file: %s", filepath)

        return self.fromString(result)

    def fromString(self, kwstr):
        return self.fromList(self._REGEX_SPLIT.split(kwstr))

    def fromList(self, kwlist):
        kwSet = set()

        for item in kwlist:
            item = item.strip()

            if item:
                kwSet.add(item)

        self._log.info("Keywords: %s", kwSet)
        return kwSet


class SearchUtilities(object):
    """
    """

    def __init__(self):
        pass


