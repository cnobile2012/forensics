# -*- coding: utf-8 -*-
#
# forensics/network.py
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
from __future__ import absolute_import

import socket
import struct


__version__ = '1.0.0'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])


class ContainerBase(object):

    def __init__(self, log, packet):
        self._log = log
        self._packet = packet
        self._parse()

    def _parse(self):
        raise NotImplementedError("Must implement the '_parse' method.")

    @property
    def data(self):
        raise NotImplementedError("Must implement the 'data' property.")


class IPContainer(ContainerBase):
    _H_SIZE = 20 # Bytes
    TCP = 0x06
    UDP = 0x11
    PROTOCOL_MAP = {TCP: 'TCP', UDP: 'UDP'}

    def __init__(self, log, packet):
        super(IPContainer, self).__init__(log, packet)

    def _parse(self):
        header = struct.unpack('!BBHHHBBH4s4s', self._packet[:self._H_SIZE])
        self._log.debug("IP Header: %s", header)
        self.version = header[0] >> 4
        self.header_length = (header[0] & 0x0f) * 4 # Convert to bytes
        self.differentiated_services = header[1]
        self.total_length = header[2]
        self.identification = header[3]
        self.flags = header[4] >> 13
        self.fragment_offset = header[4] & 0b0001111111111111
        self.ttl = header[5]
        self.protocol = header[6]
        self.checksum = header[7]
        self.src_addr = socket.inet_ntoa(header[8])
        self.dst_addr = socket.inet_ntoa(header[9])

        if self.header_length > self._H_SIZE:
            self._log.debug("IP Header is longer than %s bytes, %s option "
                            "bytes need to be parsed.", self._H_SIZE,
                            self.header_length-self._H_SIZE)

    @property
    def data(self):
        return self._packet[self.header_length:]


class TCPContainer(ContainerBase):
    _H_SIZE = 20 # Bytes

    def __init__(self, log, packet):
        super(TCPContainer, self).__init__(log, packet)

    def _parse(self):
        header = struct.unpack('!HHLLBBHHH', self._packet[:self._H_SIZE])
        self._log.debug("TCP Header: %s", header)
        self.source_port = header[0]
        self.destination_port = header[1]
        self.sequence_number = header[2]
        self.acknowledgment_number = header[3]
        self.data_offset = (header[4] >> 4) * 4 # Convert to bytes
        self.reserved = header[4] & 0x0f
        self.CWR = (header[5] >> 7) & 0x01
        self.ECE = (header[5] >> 6) & 0x01
        self.URG = (header[5] >> 5) & 0x01
        self.ACK = (header[5] >> 4) & 0x01
        self.PSH = (header[5] >> 3) & 0x01
        self.RST = (header[5] >> 2) & 0x01
        self.SYN = (header[5] >> 1) & 0x01
        self.FIN = header[5] & 0x01
        self.window_size = header[6]
        self.checksum = header[7]
        self.urgent_pointer = header[8]

        if self.data_offset > self._H_SIZE:
            self._log.debug("TCP Header is longer than %s bytes, %s option "
                            "bytes need to be parsed.", self._H_SIZE,
                            self.data_offset-self._H_SIZE)

    @property
    def data(self):
        return self._packet[self.data_offset:]


class UDPContainer(ContainerBase):
    _H_SIZE = 12 + 12 # Bytes

    def __init__(self, log, packet):
        super(UDPContainer, self).__init__(log, packet)

    def _parse(self):
        header = struct.unpack('!HHHHLLBBH', self._packet[:self._H_SIZE])
        self._log.debug("UDP Header: %s", header)
        self.source_port = header[0]
        self.destination_port = header[1]
        self.length = header[2]
        self.checksum = header[3]
        self.src_addr = socket.inet_ntoa(header[4])
        self.dst_addr = socket.inet_ntoa(header[5])
        self.reserved = header[6]
        self.protocol = header[7]
        self.total_length = header[8]

    @property
    def data(self):
        return self._packet[self.length:]
