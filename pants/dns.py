###############################################################################
#
# Copyright 2011 Stendec <stendec365@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################

###############################################################################
# Imports
###############################################################################

import itertools
import os
import random
import struct

from pants.stream import Stream
from pants.datagram import Datagram

###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger(__name__)

###############################################################################
# Constants
###############################################################################

# DNS Listening Port
DNS_PORT = 53

# Query Types
(A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT,
 RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA, LOC, NXT,
 EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT, APL, DS, SSHFP,
 IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM) = range(1,52)

# OPCODEs
OP_QUERY = 0
OP_IQUERY = 1
OP_STATUS = 2

# RCODEs
RC_NoError = 0
RC_FormatError = 1
RC_ServerFailure = 2
RC_NameError = 3
RC_NotImplemented = 4
RC_Refused = 5

# Query Classes
IN = 1

# Default Servers
DEFAULT_SERVERS = [
    '127.0.0.1',
    '8.8.8.8'
    ]

###############################################################################
# OS-Specific DNS Server Listing Code
###############################################################################

if os.name == 'nt':
    from ctypes import c_int, c_void_p, POINTER, windll, wintypes, \
                       create_string_buffer, c_char
    
    DWORD = wintypes.DWORD
    LPCWSTR = wintypes.LPCWSTR
    DNS_CONFIG_DNS_SERVER_LIST = 6

    DnsQueryConfig = windll.dnsapi.DnsQueryConfig
    DnsQueryConfig.argtypes = [
        c_int,              # __in      DNS_CONFIG_TYPE Config,
        DWORD,              # __in      DWORD Flag,
        LPCWSTR,            # __in_opt  PCWSTR pwsAdapterName,
        c_void_p,           # __in_opt  PVOID pReserved,
        POINTER(c_char),    # __out     PVOID pBuffer,
        POINTER(DWORD),     # __inout   PDWORD pBufferLength
    ]
    
    def list_dns_servers():
        # First, figure out how much data we need.
        needed = DWORD(0)
        
        result = DnsQueryConfig(DNS_CONFIG_DNS_SERVER_LIST,
                                0, None, None, None, needed)
        
        if result == 0:
            if needed.value == 0:
                # No results, apparently.
                return DEFAULT_SERVERS[:]
            else:
                result = 234
        
        if result != 234:
            raise Exception("Unexpected result calling DnsQueryConfig, %d." % result)
        
        # Now, call it.
        buf = create_string_buffer(needed.value)
        
        result = DnsQueryConfig(DNS_CONFIG_DNS_SERVER_LIST,
                                0, None, None, buf, needed)
        
        if result == 234:
            # Set the number of IPs to the space we have.
            ips = (needed.value - 4) / 4
        else:
            # Some kind of magic.
            ips = struct.unpack('I',buf[0:4])[0]
        
        # Do crazy stuff.
        out = []
        for i in xrange(ips):
            start = (i+1) * 4
            out.append(socket.inet_ntoa(buf[start:start+4]))
        
        out.extend(DEFAULT_SERVERS)
        return out
    
else:
    # *nix is way easier. Parse resolve.conf.
    def list_dns_servers():
        out = []
        try:
            with open('/etc/resolv.conf','r') as f:
                for l in f.readlines():
                    if l.startswith('nameserver '):
                        out.append(l[11:].strip())
        except IOError:
            pass
        
        out.extend(DEFAULT_SERVERS)
        return out

###############################################################################
# DNSMessage Class
###############################################################################

class DNSMessage(object):
    """
    This class stores all the information used in a DNS message, and can either
    generate valid messages to be sent to a server or read messages from a
    server.
    
    To convert an instance of DNSMessage into a byte string for sending to the
    server, simply use str() on it. To read a message from the server into an
    instance of DNSMessage, use DNSMessage.from_string().
    """
    __slots__ = ('id','qr','opcode','aa','tc','rd','ra','rcode',
                'questions','answers','authrecords','additional')
    
    def __init__(self, id=None, qr=False, opcode=OP_QUERY, aa=False, tc=False,
                    rd=True, ra=True, rcode=RC_NoError):
        
        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode
        
        self.questions = []
        self.answers = []
        self.authrecords = []
        self.additional = []
    
    def __str__(self):
        return self.toString()
    
    def toString(self, limit=None):
        out = ""
        
        ## Body
        
        for q in self.questions:
            qname, qtype, qclass = q
            
            for part in qname.split('.'):
                out += chr(len(part)) + part
            
            out += '\x00' + struct.pack('!2H', qtype, qclass)
        
        for q in itertools.chain(self.answers, self.authrecords, self.additional):
            name, typ, clss, ttl, rdata = q
            
            for part in name.split('.'):
                out += chr(len(part)) + part
            
            out += '\x00%s%s' % (
                struct.pack('!2HIH', typ, clss, ttl, len(rdata)),
                rdata
                )
        
        ## Header
        
        if limit:
            tc = len(out) + 12 > limit
            out = out[:(limit-12)]
        else:
            tc = self.tc
        
        byte3 = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | \
                (tc << 1) | self.rd
        
        byte4 = (self.ra << 7) | self.rcode
        
        
        hdr = struct.pack('!H2B4H', self.id, byte3, byte4, len(self.questions),
                len(self.answers), len(self.authrecords), len(self.additional))
        
        return hdr + out
    
    @classmethod
    def from_string(cls, data):
        """
        Create a DNSMessage instance containing the provided data in a usable
        format.
        """
        self = cls()
        
        full_data = data
        
        self.id, byte3, byte4, qdcount, ancount, nscount, arcount = \
            struct.unpack('!H2B4H', data[:12])
        
        data = data[12:]
        
        for i in xrange(qdcount):
            qname, qtype, qclass, bytes = readQuery(data, full_data)
            data = data[bytes:]
            self.questions.append((qname, qtype, qclass))
        
        for i in xrange(ancount):
            name, typ, clss, ttl, rdata, bytes = readAnswer(data, full_data)
            data = data[bytes:]
            self.answers.append((name, typ, clss, ttl, rdata))
        
        for i in xrange(nscount):
            name, typ, clss, ttl, rdata, bytes = readAnswer(data, full_data)
            data = data[bytes:]
            self.authrecords.append((name, typ, clss, ttl, rdata))
        
        for i in xrange(arcount):
            name, typ, clss, ttl, rdata, bytes = readAnswer(data, full_data)
            data = data[bytes:]
            self.additional.append((name, typ, clss, ttl, rdata))
        
        return self

###############################################################################
# Message Reading Functions
###############################################################################

def readName(data, full_data=None):
    """
    Read a QNAME from the bytes of a DNS message.
    """
    orig = len(data)
    
    name = None
    while True:
        l = ord(data[0])
        
        if full_data and l & 0xC0 == 0xC0:
            offset, = struct.unpack('!H', data[:2])
            offset ^= 0xC000
            
            if name:
                name += '.%s' % readName(full_data[offset:], full_data)[0]
            else:
                name = readName(full_data[offset:], full_data)[0]
            data = data[2:]
            break
        
        elif l == 0:
            data = data[1:]
            break
        
        if name:
            name += '.%s' % data[1:l+1]
        else:
            name = data[1:l+1]
        data = data[1+l:]
    
    return name, orig - len(data)

def readAnswer(data, full_data):
    """
    Read an answer (or similarly formatted record) from a DNS message.
    """
    orig = len(data)
    
    name, bytes = readName(data, full_data)
    data = data[bytes:]
    
    typ, clss, ttl, rdlength = struct.unpack('!2HIH', data[:10])
    data = data[10:]
    
    rdata = data[:rdlength]
    data = data[rdlength:]
    
    return name, typ, clss, ttl, rdata, orig - len(data)

def readQuery(data, full_data):
    """
    Read a query from a DNS message.
    """
    orig = len(data)
    
    qname, bytes = readName(data, full_data)
    data = data[bytes:]
    
    qtype, qclass = struct.unpack('!2H', data[:4])
    
    return qname, qtype, qclass, (orig - len(data)) + 4

