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

import os
import random
import socket
import struct

from pants.udp import UDPChannel, sendto

###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("dns")

###############################################################################
# Constants
###############################################################################

# The DNS Port
PORT = 53

# Query Types
(A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT,
 RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA, LOC, NXT,
 EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT, APL, DS, SSHFP,
 IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM) = range(1,52)

# Op-Codes
OP_QUERY = 0
OP_IQUERY = 1
OP_STATUS = 2

# Classes
IN = 1

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
                return []
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
        
        return out
    
else:
    # *nix is way easier. Parse resolve.conf.
    def list_dns_servers():
        out = []
        with open('/etc/resolv.conf','r') as f:
            for l in f.readlines():
                if l.startswith('nameserver '):
                    out.append(l[11:].strip())
        return out

###############################################################################
# Query Class
###############################################################################

class Query(object):
    def __init__(self, resolver, id=None, host=None, type=A, clss=IN,
                timeout=10, callback=None, answer=0, opcode=0, auth=0,
                trun=0, recurse_desired=1, recurse_available=0, rcode=0):
        self.resolver = resolver
        
        self.id = id
        self.host = host
        self.type = type
        self.clss = clss
        self.timeout = timeout
        self.callback = callback
        
        self.answer = answer
        self.opcode = opcode
        self.auth = auth
        self.trun = trun
        self.recurse_desired = recurse_desired
        self.recurse_available = recurse_available
        self.rcode = rcode
    
    def buildHeader(self):
        # Third Byte
        byte3 = (
            (self.answer << 7) |
            (self.opcode << 3) |
            (self.auth   << 2) |
            (self.trun   << 1) |
             self.recurse_desired )
        
        # Fourth Byte
        byte4 = (self.recurse_available << 7) | self.rcode
        
        return struct.pack('!H2B4H', self.id, byte3, byte4, 1, 0, 0, 0)
    
    def buildRequest(self):
        out = ''
        
        for part in self.host.split('.'):
            out += struct.pack('!B', len(part)) + part
        
        out += '\x00' + struct.pack('!2H', self.type, self.clss)
        
        return self.buildHeader() + out
    
###############################################################################
# RDATA Handlers
###############################################################################

rdata_process = {}

def handle(*types):
    def handler(func):
        for type in types:
            rdata_process[type] = func
        return func
    return handler

###############################################################################
# Record Reading Stuff
###############################################################################

def readName(data, full_data=None):
    orig = len(data)
    
    name = ''
    while True:
        l, = struct.unpack('!B', data[0])
        if full_data and l & 0xC0 == 192:
            offset, = struct.unpack('!H', data[:2])
            offset ^= 0xC000
            
            return readName(full_data[offset:], full_data)[0], 2
        
        if l == 0:
            data = data[1:]
            break
        if name:
            name += '.%s' % data[1:l+1]
        else:
            name = data[1:l+1]
        data = data[1+l:]
    
    return name, orig - len(data)

def readAnswer(data, full_data):
    orig = len(data)
    
    name, bytes = readName(data, full_data)
    data = data[bytes:]
    
    type, clss, ttl, rdlength = struct.unpack('!2HIH', data[:10])
    data = data[10:]
    
    rdata = data[:rdlength]
    data = data[rdlength:]
    
    if type in rdata_process:
        try:
            rdata = rdata_process[type](rdata, full_data)
        except Exception:
            log.exception('Invalid RDATA data.')
    
    return name, type, clss, ttl, rdata, orig - len(data)

def readQuery(data):
    orig = len(data)
    
    qname, bytes = readName(data)
    data = data[bytes:]
    
    qtype, qclass = struct.unpack('!2H', data[:4])
    
    return qname, qtype, qclass, (orig - len(data)) + 4

###############################################################################
# More RDATA Handlers
###############################################################################

@handle(A)
def handle_a(data, full_data):
    return socket.inet_ntoa(data)

@handle(AAAA)
def handle_aaaa(data, full_data):
    return socket.inet_ntop(AF_INET6, data)

@handle(HINFO)
def handle_hinfo(data, full_data):
    l = struct.unpack('!B', data[0])[0]
    cpu = data[1:1+l]
    data = data[1+l:]
    
    l = struct.unpack('!B', data[0])[0]
    os = data[1:1+l]
    
    return cpu, os

@handle(MINFO, RP)
def handle_minfo(data, full_data):
    rmailbx, bytes = readName(data, full_data)
    return rmailbx, readName(data[bytes:], full_data)[0]

@handle(MX)
def handle_mx(data, full_data):
    preference, = struct.unpack('!H', data[:2])
    return preference, readName(data[2:], full_data)[0]

@handle(NS,MD,MF,CNAME,MB,MG,MR,PTR,DNAME)
def handle_many(data, full_data):
    return readName(data, full_data)[0]
    
@handle(SOA)
def handle_soa(data, full_data):
    mname, bytes = readName(data, full_data)
    data = data[bytes:]
    
    rname, bytes = readName(data, full_data)
    data = data[bytes:]
    
    serial, refresh, retry, expire, minimum = struct.unpack('!LlllL', data[:20])
    
    return mname, rname, serial, refresh, retry, expire, minimum

@handle(SRV)
def handle_srv(data, full_data):
    priority, weight, port = struct.unpack('!HHH', data[:6])
    target = readName(data[6:], full_data)[0]
    
    return priority, weight, port, target
    
@handle(WKS)
def handle_wks(data, full_data):
    address = socket.inet_ntoa(data[:4])
    protocol = struct.unpack('!B', data[4])
    
    return address, protocol, data[5:]

###############################################################################
# Resolver Class
###############################################################################
    
class Resolver(object):
    def __init__(self, servers=None, channel=None):
        """
        Initialize the Resolver instance.
        
        Args:
            servers: A list of DNS servers to query, in order, for any
                given queries. If None, a list of suitable servers will be
                retrieved from the OS.
            channel: A UDPChannel object to bind the Resolver to. One will be
                created if one is not supplied.
        """
        # Internal State
        self.messages = {}
        self.cache = {}
        self._channel = channel or UDPChannel()
        
        self._last_id = -1
        
        # Somewhat Less Internal State
        self.servers = servers or list_dns_servers()
        
        # Start the Channel on a random port.
        self._channel.handle_read = self._got_something
        
        self.port = random.randrange(10005, 65535)
        self._start = self.port - 1
        
        while True:
            try:
                self._channel.listen(self.port)
                break
            except Exception, e:
                print repr(e)
                self.port += 1
                if self.port > 65535:
                    self.port = 10000
                if self.port == self._start:
                    raise Exception("Can't listen on any port.")
    
    def _got_something(self, data):
        """
        This is called when we receive a message. Check it out.
        """
        
        full_data = data
        
        id, byte3, byte4, qdcount, ancount, nscount, arcount = struct.unpack(
            '!H2B4H', data[:12])
        
        data = data[12:]
        
        # Skip through all the queries.
        queries = []
        for i in xrange(qdcount):
            qname, qtype, qclass, bytes = readQuery(data)
            data = data[bytes:]
            queries.append((qname, qtype, qclass))
            
        # Read the answers.
        answers = []
        for i in xrange(ancount):
            name, type, clss, ttl, rdata, bytes = readAnswer(data, full_data)
            data = data[bytes:]
            
            answers.append((name, type, clss, ttl, rdata))
        
        # Read the name server records in the authority section.
        nswers = []
        for i in xrange(nscount):
            name, type, clss, ttl, rdata, bytes = readAnswer(data, full_data)
            data = data[bytes:]
            
            nswers.append((name, type, clss, ttl, rdata))
        
        # Read the additional records.
        additional = []
        for i in xrange(arcount):
            name, type, clss, ttl, rdata, bytes = readAnswer(data, full_data)
            data = data[bytes:]
            
            additional.append((name, type, clss, ttl, rdata))
        
        # Now, figure out what to do with it.
        if not id in self.messages:
            return
        
        msg = self.messages[id]
        
        for i in answers:
            if i[1] == msg.type:
                # Found our answer.
                if not msg.host in self.cache:
                    self.cache[msg.host] = {}
                self.cache[msg.host][msg.type] = i[4]
                self._safely_call(msg.callback, msg.host, msg.type, i[4],
                        answers, nswers, additional)
                break
        else:
            self._safely_call(msg.callback, msg.host, msg.type, None, answers, nswers, additional)
        
        if id in self.messages:
            del self.messages[id]
    
    def _safely_call(self, callback, *args, **kwargs):
        try:
            callback(*args, **kwargs)
        except Exception:
            log.exception('Error calling callback for DNS result.')
    
    def query(self, host, type=A, clss=IN, timeout=10, callback=None, cache=True):
        """
        Make a DNS request.
        
        Args:
            host: The host to request information for.
            type: The DNS query type. Defaults to A.
            clss: The class of the records being requested. Defaults to IN.
            timeout: How long to wait for a response, in seconds, before
                erroring out.
            callback: A function to call once the request has been responded
                to. Can be None, for some weird reason.
            cache: If True, a cached value will be returned. If you want
                additional records to be returned, this must be False.
        """
        if cache and host in self.cache and type in self.cache[host]:
            if callback:
                self._safely_call(callback, host, type, self.cache[host][type],
                    [], [], [])
            return
        
        # Increment the Last ID
        self._last_id += 1
        if self._last_id > 65535:
            self._last_id = 0
        id = self._last_id
        
        # Store this message's details.
        self.messages[id] = msg = Query(
                                self, id, host, type, clss, timeout, callback)
        
        # Send the Request
        self._channel.write(msg.buildRequest(), (self.servers[0], PORT))
    
resolver = Resolver()

###############################################################################
# Helper Functions
###############################################################################

query = resolver.query