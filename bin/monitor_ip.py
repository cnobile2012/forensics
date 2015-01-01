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
    setupLogger, validatePath, ContainerBase, TCPContainer, UDPContainer,
    IPContainer)


__version__ = '1.0.0'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])


class MonitorIP(object):
    _PACKET_SIZE = 65535

    def __init__(self, log, options, protocols):
        self._log = log
        self._options = options
        self._protocols = protocols
        self._conn = None
        self._cursor = None

    def start(self):
        if self._options.data_path:
            if self._options.dump_db:
                self.dumpDB()
            else:
                self._cursor = self._configDB()
                self._monitor()
        else:
            self._monitor()

    def _configDB(self):
        self._conn = sqlite3.connect(self._options.data_path)
        cursor = self._conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS monitor_ip "
                       "(protocol text, address text, port integer, "
                       "datetime text)")
        return cursor

    def _monitor(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        while True:
            packet = soc.recv(self._PACKET_SIZE)
            ipCont = IPContainer(self._log, packet)
            Klass = IPContainer.PROTOCOL_CLASS_MAP.get(ipCont.protocol)

            if not issubclass(Klass, ContainerBase):
                self._log.info("Non-implemented protocol %s.",
                               hex(ipCont.protocol))
                continue

            if self._protocols and Klass.name() not in self._protocols:
                self._log.debug("Protocol: %s rejected.", Klass)
                continue

            address = self._options.address

            if address and ipCont.dst_addr not in address:
                self._log.debug("Address %s rejected.", ipCont.dst_addr)
                continue

            obj = Klass(self._log, ipCont.data)
            ports = self._options.ports

            if ports and obj.destination_port not in ports:
                self._log.debug("Port %s rejected.", obj.destination_port)
                continue

            if hasattr(pytz, 'utc'):
                now = datetime.datetime.now(pytz.utc).isoformat()
            else:
                now = datetime.datetime.utcnow().isoformat()

            if self._cursor:
                self._insert(Klass.name(), ipCont.src_addr,
                             obj.destination_port, now)

            self._log.info("Protocol: %s, Source Address: %s, "
                           "Destination Address: %s, UTC time: %s",
                           obj, ipCont.src_addr, ipCont.dst_addr, now)
            self._log.info("Protocol: %s, Source Port: %s, "
                           "Destination Port: %s", obj, obj.source_port,
                           obj.destination_port)

    def _insert(self, protocol, addr, port, dtime):
        self._cursor.execute("INSERT INTO monitor_ip VALUES (?,?,?,?)",
                             (protocol, addr, port, dtime))
        self._conn.commit()

    def closeDB(self):
        if self._conn:
            self._conn.close()

    def dumpDB(self, stream=sys.stdout):
        conn = sqlite3.connect(self._options.data_path)

        for record in conn.iterdump():
            stream.write("{}\n".format(record))


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
        help="IP address' to monitor seperated with spaces or commas.")
    parser.add_argument(
        '-p', '--ports', type=str, default='', dest='ports',
        help="Port(s) to monitor seperated with spaces or commas.")
    parser.add_argument(
        '-T', '--tcp', action='store_true', default=False, dest='tcp',
        help="Look for the TCP protocol.")
    parser.add_argument(
        '-U', '--udp', action='store_true', default=False, dest='udp',
        help="Look for the UDP protocol.")
    parser.add_argument(
        '-d', '--data-path', type=str, default='', dest='data_path',
        help="Path to SQLite database file.")
    parser.add_argument(
        '-b', '--dump-db', action='store_true', dest='dump_db',
        help="Dump the database if it exists.")

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

    if not validatePath(options.data_path, sqlite=True):
        msg = "The data path seems to not exist, please check: {}".format(
            options.data_path)
        log.critical(msg)
        if options.quite: print(msg)
        sys.exit(1)

    protocols = []

    if options.tcp:
        protocols.append("TCP")

    if options.udp:
        protocols.append("UDP")

    if options.ports:
        options.ports = [int(p.strip())
                         for p in options.ports.replace(' ', ',').split(',')
                         if p and p.isdigit()]

    if options.address:
        options.address = [a.strip()
                           for a in options.address.replace(' ', ',').split(',')
                           if a]

    log.debug("Options: %s", options)
    mip = None

    try:
        log.info("Monitoring protocol(s) %s, started at %s",
                 protocols, startTime)
        mip = MonitorIP(log, options, protocols)
        mip.start()
        endTime = datetime.datetime.now()
        log.info("Monitoring protocol(s) %s, finished at %s, elapsed time %s",
                 protocols, endTime, endTime - startTime)
    except Exception as e:
        if mip: mip.closeDB() # Close the database if exists.

        if options.quite:
            tb = sys.exc_info()[2]
            traceback.print_tb(tb)
            print("{}: {}\n".format(sys.exc_info()[0], sys.exc_info()[1]))

        sys.exit(1)

    sys.exit(0)
