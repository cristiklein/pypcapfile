"""
IP protocol definitions.
"""

import binascii
import ctypes
import struct


class IP(ctypes.Structure):
    """
    Represents an IP packet.
    """

    _fields_ = [('v', ctypes.c_ushort),         # version
                ('hl', ctypes.c_ushort),        # internet header length
                ('tos', ctypes.c_ubyte),        # type of service
                ('len', ctypes.c_ushort),       # total length
                ('id', ctypes.c_ushort),        # IPID
                ('flags', ctypes.c_ushort, 3),  # flags
                ('off', ctypes.c_ushort, 13),   # fragmentation offset
                ('ttl', ctypes.c_ubyte),        # TTL
                ('p', ctypes.c_ubyte),          # protocol
                ('sum', ctypes.c_ushort),       # checksum
                ('src', ctypes.c_uint32),       # source
                ('dst', ctypes.c_uint32)]       # destination

    def __init__(self, packet, layers=0):
        # parse the required header first, deal with options later
        fields = struct.unpack('!BBHHHBBHII', packet[:20])
        self.v = fields[0] >> 4
        self.hl = fields[0] & 0x0f
        assert self.v == 4 and self.hl > 4, 'not an IPv4 packet.'
        self.tos = fields[1]
        self.len = fields[2]
        self.id = fields[3]
        self.flags = fields[4] >> 13
        self.off = fields[4] & 0x1fff
        self.ttl = fields[5]
        self.p = fields[6]
        self.sum = fields[7]
        self.src = fields[8]
        self.dst = fields[9]

        if self.hl > 5:
            payload_start = self.hl * 4
            self.opt = packet[0x14:payload_start]
            self.payload = packet[payload_start:]
            self.opt_parsed = parse_options(self.opt)
        else:
            self.opt = b''
            self.payload = packet[0x14:]
            self.opt_parsed = { }

        self.pad = b''

        if layers:
            self.load_transport(layers)

    def load_transport(self, layers=1):
        if layers:
            ctor = payload_type(self.p)[0]
            if ctor:
                ctor = ctor
                payload = self.payload
                self.payload = ctor(payload, layers - 1)
            else:
                pass

    def __str__(self):
        packet = 'ipv4 packet from %s to %s carrying %d bytes'
        packet = packet % (pretty_ip_addr(self.src), pretty_ip_addr(self.dst), len(self.payload))
        return packet

def pretty_ip_addr(addr):
    return '.'.join([
        str((addr >> 24) & 0xFF),
        str((addr >> 16) & 0xFF),
        str((addr >>  8) & 0xFF),
        str((addr >>  0) & 0xFF),
    ])

def strip_ip(packet):
    """
    Remove the IP packet layer, yielding the transport layer.
    """
    if not type(packet) == IP:
        packet = IP(packet)
    payload = packet.payload

    if type(payload) == '':
        payload = payload
    return payload


def __call__(packet):
    return IP(packet)

def payload_type(protocol):
    if protocol == 0x11:
        from pcapfile.protocols.transport.udp import UDP
        return (UDP, 'UDP')
    elif protocol == 0x06:
        from pcapfile.protocols.transport.tcp import TCP
        return (TCP, 'TCP')
    else:
        return (None, 'unknown')

def parse_options(opt_bytes):
    opts = { }

    i = 0
    l = len(opt_bytes) # unprocessed length
    while l:
        opt_type = opt_bytes[i]
        if opt_type == 0: # end
            break
        if opt_type == 1: # NOP
            i += 1
            l -= 1
            continue

        if l < 2:
            break # invalid
        opt_len = opt_bytes[i+1]
        if opt_len < 2 or opt_len > l:
            break # invalid

        # Custom options parsing goes here
        if opt_type == 0x55:
            if opt_len < 1+1+2+4+8:
                break # invalid
            _, _, _, _, uat = struct.unpack('!BBHIQ', opt_bytes[:16])
            opts['uat'] = uat

        i += opt_len
        l -= opt_len

    return opts
