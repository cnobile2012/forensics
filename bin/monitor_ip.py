#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

import os
import sys
import logging
import traceback
import argparse
import datetime
import socket
import sqlite3

try:
    import pytz
except:
    pytz = None

LOCAL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

if os.path.isdir(os.path.join(LOCAL_PATH, 'forensics')):
    sys.path.insert(0, LOCAL_PATH)

from forensics import (
    setupLogger, validatePath, TCPContainer, UDPContainer, IPContainer)


__version__ = '1.0.0'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])


class MonitorIP(object):
    _PACKET_SIZE = 65535

    def __init__(self, log, options):
        self._log = log
        self._options = options
        self._conn = None
        self._cursor = None

    def start(self):
        if self._options.data_path:
            if self._options.dump_db:
                self.dumpDB()
            else:
                self._cursor = self._configDB()
                self._monitor()

    def _configDB(self):
        self._conn = sqlite3.connect(self._options.data_path)
        cursor = self._conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS monitor_ip "
                       "(address text, port integer, datetime text)")
        return cursor

    def _monitor(self):
        address = self._options.address
        port = int(self._options.port)
        protocol = self._options.protocol

        if not hasattr(IPContainer, protocol):
            self._log.critical("Non-implemented protocol: %s", protocol)
            return

        soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        while True:
            packet = soc.recv(self._PACKET_SIZE)
            ipCont = IPContainer(self._log, packet)

            if (ipCont.protocol == IPContainer.TCP and
                ipCont.dst_addr == address):
                tcpCont = TCPContainer(self._log, ipCont.data)
                self._log.debug("Destination Port: %s, Sniffing Port: %s",
                                tcpCont.destination_port, port)

                if tcpCont.destination_port == port:
                    if hasattr(pytz, 'utc'):
                        now = datetime.datetime.now(pytz.utc).isoformat()
                    else:
                        now = datetime.datetime.utcnow().isoformat()

                    if self._cursor:
                        self._insert(ipCont.src_addr,
                                     tcpCont.destination_port,
                                     now)

                    self._log.info("Source Address: %s, "
                                   "Destination Address: %s, UTC time: %s",
                                   ipCont.src_addr, ipCont.dst_addr, now)
                    self._log.info("Source Port: %s, Destination Port: %s",
                                   tcpCont.source_port,
                                   tcpCont.destination_port)

    def _insert(self, addr, port, dtime):
        self._cursor.execute("INSERT INTO monitor_ip VALUES (?,?,?)",
                             (addr, port, dtime))
        self._conn.commit()

    def closeDB(self):
        if self._conn:
            self._conn.close()

    def dumpDB(self, stream=sys.stdout):
        conn = sqlite3.connect(self._options.data_path)

        for record in conn.iterdump():
            stream.write("{}\n".format(record))
            self._log.info("DUMP: %s", record)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=("Forensic IP monitor."))
    parser.add_argument(
        '-n', '--noop', action='store_true', default=False, dest='noop',
        help="Run as if doing something, but do nothing.")
    parser.add_argument(
        '-q', '--quite', action='store_false', dest='quite',
        help="Turn off all console logging.")
    parser.add_argument(
        '-D', '--debug', action='store_true', dest='debug',
        help="Turn on DEBUG logging mode, can be very verbose.")
    parser.add_argument(
        '-l', '--log-file', type=str, default='', dest='log_file',
        help="Log file path and filename.")
    parser.add_argument(
        '-a', '--address', type=str, default='', dest='address',
        required=False, help="IP address to monitor.")
    parser.add_argument(
        '-p', '--port', type=str, default='', dest='port',
        required=False, help="Port to monitor.")
    parser.add_argument(
        '-P', '--protocol', type=str, default='', dest='protocol',
        required=False, help="Protocol to monitor.")
    parser.add_argument(
        '-d', '--data-path', type=str, default='', dest='data_path',
        required=False, help="Path to SQLite database file.")
    parser.add_argument(
        '-b', '--dump-db', action='store_true', dest='dump_db',
        required=False, help="Dump the database if it exists.")

    options = parser.parse_args()

    if not options.quite and options.log_file == u'':
        level = 1000 # Turns off console logging if a file is not defined.
    elif options.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    log = setupLogger(fullpath=options.log_file, level=level)
    log.debug("Options: %s", options)
    startTime = datetime.datetime.now()
    head, tail = os.path.split(options.data_path)

    if head != '' and not validatePath(head, dir=True):
        msg = "The data path seems to not exist, please check: {}".format(head)
        log.critical(msg)
        if options.quite: print(msg)
        sys.exit(1)

    requiredTogether = (options.address, options.port, options.protocol)

    if any(requiredTogether) and not all(requiredTogether):
        msg = "Arguments address, port, and protocol must be used together."
        log.critical(msg)
        if options.quite: print(msg)
        sys.exit(1)

    ip = None

    try:
        log.info("Monitoring protocol %s on port %s--started at %s",
                 options.protocol, options.port, startTime)
        ip = MonitorIP(log, options)
        ip.start()
        endTime = datetime.datetime.now()
        log.info("Monitoring protocol %s on port %s--finished at %s, "
                 "elapsed time %s", options.protocol, options.port, endTime,
                 endTime - startTime)
    except Exception as e:
        if ip: ip.closeDB() # Close the database if exists.

        if options.quite:
            tb = sys.exc_info()[2]
            traceback.print_tb(tb)
            print "%s: %s\n" % (sys.exc_info()[0], sys.exc_info()[1])

        sys.exit(1)

    sys.exit(0)
