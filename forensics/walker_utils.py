# -*- coding: utf-8 -*-
#
# forensics/walker_utils.py
#
# by: Carl J.Nobile
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

import os
import stat
import time
import hashlib
import csv
from collections import OrderedDict


__version__ = '1.0.0'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])


class WalkerUtilities(object):
    """
    This class contains utility methods used for walking through a directory
    tree and gathering information about files.
    """
    _STAT_TO_CONTAINER = (('st_mode', 'mode'), ('st_uid', 'owner'),
                          ('st_gid', 'group'), ('st_size', 'size'),
                          ('st_atime', 'atime'), ('st_mtime', 'mtime'),
                          ('st_ctime', 'ctime'))
    _MD5 = 'MD5'
    _SHA256 = 'SHA256'
    _SHA512 = 'SHA512'

    def __init__(self, log, options):
        self._log = log
        self._options = options
        self._hashType = {options.md5: self._MD5,
                          options.sha256: self._SHA256,
                          options.sha512: self._SHA512}.get(True)
        RowContainer.setHashHeader(self._hashType)

    def walkPath(self):
        """
        Walk the path generating info for each file found.
        """
        processCount = 0

        if not self._options.noop:
            with open(self._options.report_path, 'w') as outFile:
                writer = csv.writer(outFile, delimiter=',',
                                    quoting=csv.QUOTE_ALL)
                writer.writerow(RowContainer.HEADERS)

                for root, dirs, files in os.walk(self._options.dir_path,
                                                 onerror=self.__handleError):
                    for file in files:
                        row = self._generateFileInfo(root, file)
                        writer.writerow(row)
                        processCount += 1

        return processCount

    def __handleError(self, e):
        self._log.error("Error found with file: %s, %s", e.filename, e)

    def _generateFileInfo(self, root, file):
        fname = os.path.join(root, file)

        try:
            with open(fname, 'rb') as inFile:
                row = self._gatherRowStats(inFile.read(), fname)
        except IOError as e:
            self._log.warn("Error opening file: %s, %s", fname, e)
            row = []

        return row

    def _hashMD5(self, data):
        digest = hashlib.md5()
        digest.update(data)
        return digest.hexdigest().upper()

    def _hashSHA256(self, data):
        digest = hashlib.sha256()
        digest.update(data)
        return digest.hexdigest().upper()

    def _hashSHA512(self, data):
        digest = hashlib.sha512()
        digest.update(data)
        return digest.hexdigest().upper()

    HASH_MAP = {_MD5: _hashMD5, _SHA256: _hashSHA256, _SHA512: _hashSHA512}

    def _gatherRowStats(self, data, fname):
        rc = RowContainer(self._log)
        statInfo = os.lstat(fname)

        # Set the stat elements.
        for stat, cont in self._STAT_TO_CONTAINER:
            rc.setColumn(cont, getattr(statInfo, stat))

        head, tail = os.path.split(fname)
        root, ext = os.path.splitext(tail)
        rc.setColumn('path', head)
        rc.setColumn('file', tail)
        rc.setColumn('type', ext.strip('.'))
        rc.setColumn('hash', self.HASH_MAP.get(self._hashType)(self, data))
        return rc.serialize()


class RowContainer(object):
    """
    This class stores the values for a row of data, it also hold the headers
    used in the CVS output file.
    """
    HEADERS = ['File', 'Path', 'Type', 'Size', 'Modified Time (ISO)',
               'Access Time (ISO)', 'Created Time (ISO)', "{}", 'Owner',
               'Group', 'Mode']
    __LOCAL_FUNC = ('atime', 'mtime', 'ctime', 'mode')

    def __init__(self, log):
        self._log = log

    def _utcTime(self, seconds):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))

    def _mode(self, value):
        return oct(value & 0xfff)

    COLUMN_MAP = OrderedDict((
        ('file', lambda x: x), ('path', lambda x: x), ('type', lambda x: x),
        ('size', str), ('atime', _utcTime), ('mtime', _utcTime),
        ('ctime', _utcTime), ('hash', lambda x: x), ('owner', str),
        ('group', str), ('mode', _mode)))

    @classmethod
    def setHashHeader(self, value):
        idx = self.HEADERS.index('{}')
        self.HEADERS[idx] = self.HEADERS[idx].format(value)

    def serialize(self):
        row = []

        try:
            for col in self.COLUMN_MAP:
                row.append(getattr(self, col))
        except AttributeError as e:
            self._log.critical("Member object '%s' has not been set on this "
                               "instance of %s", col, self.__class__.__name__)
            raise e

        self._log.debug("Row: %s", row)
        return row

    def setColumn(self, name, value):
        func = self.COLUMN_MAP.get(name)

        if name in self.__LOCAL_FUNC:
            value = func(self, value)
        else:
            value = func(value)

        setattr(self, name, value)
        self._log.debug("Set '%s' to '%s'", name, value)
