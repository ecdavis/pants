###############################################################################
#
# Copyright 2011 Pants Developers (see AUTHORS.txt)
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
"""
Implementation of the DNS protocol for use in Pants.
"""

###############################################################################
# Imports
###############################################################################

import collections
import functools
import itertools
import os
import random
import socket
import struct
import time

import pants.engine
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

# Return Values
DNS_TIMEOUT = -1
DNS_OK = 0
DNS_FORMATERROR = 1
DNS_SERVERFAILURE = 2
DNS_NAMEERROR = 3
DNS_NOTIMPLEMENTED = 4
DNS_REFUSED = 5

# DNS Listening Port
DNS_PORT = 53

# Query Types
(A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT,
 RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA, LOC, NXT,
 EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT, APL, DS, SSHFP,
 IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM) = range(1,52)

QTYPES = "A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA, LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM".split(', ')

# OPCODEs
OP_QUERY = 0
OP_IQUERY = 1
OP_STATUS = 2

# Query Classes
IN = 1

# Default Servers
DEFAULT_SERVERS = [
    '127.0.0.1',
    '8.8.8.8'
    ]

# Internal Exception
class TooShortError(ValueError):
    pass

# RDATA Declarations
RDATA_TYPES = {
    A: (('address', 'ipv4'), ),
    NS: 'name',
    MD: 'name',
    MF: 'name',
    CNAME: 'name',
    SOA: (('mname', 'name'), ('rname', 'name'), ('serial|refresh|retry|expire|minimum', '!LlllL')),
    MB: 'name',
    MG: 'name',
    MR: 'name',
    NULL: 'str',
    WKS: (('address', 'ipv4'), ('protocol', '!B'), ('map', 'str')),
    PTR: 'name',
    HINFO: (('cpu', 'lstr'), ('os', 'lstr')),
    MINFO: (('rmailbx', 'name'), ('emailbx', 'name')),
    MX: (('preference', '!H'), ('name', 'name')),
    TXT: 'strs',
    RP: (('mbox', 'name'), ('txt', 'name')),

    AAAA: (('address', 'ipv6'), ),

    SRV: (('priority|weight|port', '!3H'), ('target', 'name')),

    DNAME: 'name',

    DNSKEY: (('flags|protocol|algorithm', '!H2B'), ('key', 'str')),
    }

RDATA_TUPLES = {}

for k,v in RDATA_TYPES.iteritems():
    # Get the Name.
    nm = '%s_Record' % QTYPES[k-1]

    if v == 'strs':
        continue

    elif v == 'str':
        RDATA_TUPLES[k] = collections.namedtuple(nm, ['value'])
        continue

    elif v == 'name':
        RDATA_TUPLES[k] = collections.namedtuple(nm, ['name'])
        continue

    keys = []
    for fn, ft in v:
        if '|' in fn:
            keys.extend(fn.split('|'))
        else:
            keys.append(fn)
    
    RDATA_TUPLES[k] = collections.namedtuple(nm, keys)

###############################################################################
# OS-Specific DNS Server Listing and hosts Code
###############################################################################

if os.name == 'nt':
    from ctypes import c_int, c_void_p, POINTER, windll, wintypes, \
                       create_string_buffer, c_char, c_char_p, c_size_t

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

    # Additional Functions
    if not hasattr(socket, 'inet_pton') and hasattr(windll, 'ws2_32') and hasattr(windll.ws2_32, 'inet_pton'):
        _inet_pton = windll.ws2_32.inet_pton
        _inet_pton.argtypes = [
            c_int,              # __in  INT Family,
            c_char_p,           # __in  PCTSTR pszAddrString,
            POINTER(c_char),    # __out PVOID pAddrBuf
            ]

        def inet_pton(address_family, ip_string):
            """
            Convert an IP address from its family-specific string format to a
            packed, binary format. inet_pton() is useful when a library or
            network protocol calls for an object of type ``struct in_addr`` or
            ``struct in6_addr``.

            ===============  ============
            Argument         Description
            ===============  ============
            address_family   Supported values are ``socket.AF_INET`` and ``socket.AF_INET6``.
            ip_string        The IP address to pack.
            ===============  ============
            """
            if not address_family in (socket.AF_INET, socket.AF_INET6):
                raise socket.error(97, os.strerror(97))

            if address_family == socket.AF_INET:
                bytes = 5
            else:
                bytes = 17

            buf = create_string_buffer(bytes)

            result = _inet_pton(address_family, ip_string, buf)
            if result == 0:
                raise socket.error("illegal IP address string passed to inet_pton")
            elif result != 1:
                raise socket.error("unknown error calling inet_pton")

            return buf.raw[:bytes-1]

        socket.inet_pton = inet_pton

    if not hasattr(socket, 'inet_ntop') and hasattr(windll, 'ws2_32') and hasattr(windll.ws2_32, 'inet_ntop'):
        _inet_ntop = windll.ws2_32.inet_ntop
        _inet_ntop.argtypes = [
            c_int,              # __in  INT Family,
            POINTER(c_char),    # __in  PVOID pAddr,
            c_char_p,           # __out PTSTR pStringBuf,
            c_size_t,           # __in  size_t StringBufSize
            ]

        def inet_ntop(address_family, packed_ip):
            """
            Convert a packed IP address (a string of some number of characters)
            to its standard, family-specific string representation (for
            example, ``'7.10.0.5`` or ``5aef:2b::8``). inet_ntop() is useful
            when a library or network protocol returns an object of type
            ``struct in_addr`` or ``struct in6_addr``.

            ===============  ============
            Argument         Description
            ===============  ============
            address_family   Supported values are ``socket.AF_INET`` and ``socket.AF_INET6``.
            packed_ip        The IP address to unpack.
            ===============  ============
            """
            if not address_family in (socket.AF_INET, socket.AF_INET6):
                raise socket.error(97, os.strerror(97))

            if address_family == socket.AF_INET:
                bytes = 17
            else:
                bytes = 47

            buf = create_string_buffer(bytes)

            result = _inet_ntop(address_family, packed_ip, buf, bytes)
            if not result:
                raise socket.error("unknown error calling inet_ntop")

            return buf.value

        socket.inet_ntop = inet_ntop

    host_path = os.path.join(os.path.expandvars("%SystemRoot%"), "system32", "drivers", "etc", "hosts")

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

    host_path = "/etc/hosts"

###############################################################################
# Hosts
###############################################################################

hosts = {A: {}, AAAA: {}}
host_m = None
host_time = None

def load_hosts():
    global host_m
    global host_time

    host_time = time.time()

    try:
        stat = os.stat(host_path)
        if hosts and host_m is not None:
            if host_m == (stat.st_mtime, stat.st_size):
                return

        hosts[A].clear()
        hosts[AAAA].clear()

        with open(host_path, 'r') as f:
            for l in f.readlines():
                l = l.strip().split(None, 1)
                if len(l) < 2 or l[0].startswith('#') or not all(l):
                    continue
                ip = l[0].strip()
                host = [x.strip() for x in l[1].split()]

                try:
                    socket.inet_aton(ip)

                    for h in host:
                        hosts[A][h] = ip

                except socket.error:
                    if hasattr(socket, 'inet_pton'):
                        try:
                            socket.inet_pton(socket.AF_INET6, ip)

                            for h in host:
                                hosts[AAAA][h] = ip

                        except socket.error:
                            continue

        host_m = (stat.st_mtime, stat.st_size)
    except (OSError, ValueError):
        pass

    if not 'localhost' in hosts[A]:
        hosts[A]['localhost'] = '127.0.0.1'

    if not 'localhost' in hosts[AAAA]:
        hosts[AAAA]['localhost'] = '::1'

load_hosts()

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
    __slots__ = ('id','qr','opcode','aa','tc','rd','ra','rcode','server',
                'questions','answers','authrecords','additional')

    def __init__(self, id=None, qr=False, opcode=OP_QUERY, aa=False, tc=False,
                    rd=True, ra=True, rcode=DNS_OK):

        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode

        self.server = None

        self.questions = []
        self.answers = []
        self.authrecords = []
        self.additional = []

    def __str__(self):
        return self.to_string()

    def to_string(self, limit=None):
        """
        Render the DNSMessage as a string of bytes that can be sent to a DNS
        server. If a *limit* is specified and the length of the string exceeds
        that limit, the truncated byte will automatically be set to True.

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        limit      None      *Optional.* The maximum size of the message to generate, in bytes.
        =========  ========  ============
        """
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

        =========  ============
        Argument   Description
        =========  ============
        data       The data to parse into a DNSMessage instance.
        =========  ============
        """
        if len(data) < 12:
            raise TooShortError

        self = cls()

        full_data = data

        self.id, byte3, byte4, qdcount, ancount, nscount, arcount = \
            struct.unpack('!H2B4H', data[:12])

        self.qr = bool(byte3 >> 7)
        self.opcode = (byte3 & 120) >> 3
        self.aa = bool((byte3 & 4) >> 2)
        self.tc = bool((byte3 & 2) >> 1)
        self.rd = bool(byte3 & 1)

        self.ra = bool(byte4 >> 7)
        self.rcode = byte4 & 15

        data = data[12:]

        try:
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

        except TooShortError:
            if not self.tc:
                raise

        return self

###############################################################################
# Message Reading Functions
###############################################################################

def readName(data, full_data=None):
    """
    Read a QNAME from the bytes of a DNS message.
    """
    if not data:
        raise TooShortError

    orig = len(data)

    name = None
    while True:
        if not data:
            raise TooShortError

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

        if len(data) < 1 + l:
            raise TooShortError

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
    if not data:
        raise TooShortError

    orig = len(data)

    name, bytes = readName(data, full_data)
    data = data[bytes:]

    if len(data) < 10:
        raise TooShortError

    typ, clss, ttl, rdlength = struct.unpack('!2HIH', data[:10])
    data = data[10:]

    if not data or len(data) < rdlength:
        raise TooShortError

    rdata = readRDATA(data[:rdlength], full_data, typ)
    data = data[rdlength:]

    return name, typ, clss, ttl, rdata, orig - len(data)

def readQuery(data, full_data):
    """
    Read a query from a DNS message.
    """
    if not data:
        raise TooShortError

    orig = len(data)

    qname, bytes = readName(data, full_data)
    data = data[bytes:]

    if len(data) < 4:
        raise TooShortError

    qtype, qclass = struct.unpack('!2H', data[:4])

    return qname, qtype, qclass, (orig - len(data)) + 4

def readRDATA(data, full_data, qtype):
    """
    Read RDATA for a given QTYPE into an easy-to-use namedtuple.
    """
    if not qtype in RDATA_TYPES:
        return data

    format = RDATA_TYPES[qtype]

    # Special cast for TXT.
    if format == 'strs':
        values = []
        while data:
            l = ord(data[0])
            values.append(data[1:1+l:])
            data = data[1+l:]
        return tuple(values)

    tup = RDATA_TUPLES[qtype]

    if format == 'name':
        return tup(readName(data, full_data)[0])

    values = []
    for fn, ft in format:
        if ft == 'ipv4':
            values.append(socket.inet_ntoa(data[:4]))
            data = data[4:]

        elif ft == 'ipv6':
            if hasattr(socket, 'inet_ntop'):
                values.append(socket.inet_ntop(socket.AF_INET6, data[:16]))
            else:
                values.append(data[:16])
            data = data[16:]

        elif ft == 'lstr':
            l = ord(data[0])
            values.append(data[1:1+l])
            data = data[1+l:]

        elif ft == 'name':
            v, bytes = readName(data, full_data)
            data = data[bytes:]
            values.append(v)

        elif ft == 'str':
            values.append(data)
            data = ''

        else:
            sz = struct.calcsize(ft)
            values.extend(struct.unpack(ft, data[:sz]))
            data = data[sz:]

    return tup(*values)


###############################################################################
# Resolver Class
###############################################################################

class Resolver(object):
    """
    The Resolver class makes DNS queries and extracts useful information from
    the responses. It caches that information and returns it to provided
    callback functions. The bulk of the heavy lifting is done in the
    :class:`DNSMessage` class and the RDATA handling functions.
    
    =========  =========  ============
    Argument   Default    Description
    =========  =========  ============
    servers    ``None``   *Optional.* A list of DNS servers to query. If a list isn't provided, Pants will query the operating system for a list of servers, falling back to a list of default servers if none are available.
    cache      ``None``   *Optional.* An object to use for caching DNS records. If one isn't provided, an empty dictionary will be used.
    =========  =========  ============
    """
    def __init__(self, servers=None, cache=None):
        # Somewhat Public State
        self.servers = servers or list_dns_servers()
        self.cache = cache or {}
        
        # Internal State
        self._messages = {}
        self._socket = None
        self._last_id = -1
    
    def _initialize_udp(self):
        """ Create a new Datagram instance and listen on a socket. """
        self._socket = Datagram()
        self._socket.on_read = self.receive_message
        
        start = port = random.randrange(10005, 65535)
        while True:
            try:
                self._socket.listen(('',port))
                break
            except Exception:
                port += 1
                if port > 65535:
                    port = 10000
                if port == start:
                    raise Exception("Can't listen on any port.")
    
    def _safely_call(self, callback, *args, **kwargs):
        try:
            callback(*args, **kwargs)
        except Exception:
            log.exception('Error in DNS callback.')
    
    ##### Cache Control ########################################################
    
    def get_cached(self, name, qtype, qclass):
        """
        Attempt to return a value from the cache. If an entry doesn't exist, or
        if it's old, return None.
        """
        key = (qtype, qclass)
        
        if name in self.cache and key in self.cache[name]:
            death, ttl, rdata = self.cache[name][key]
            
            if death < time.time():
                # Clear out the old record
                del self.cache[name][key]
                if not self.cache[name]:
                    del self.cache[name]
            else:
                return ttl, rdata
        
        return None
    
    def _set_cached(self, name, qtype, qclass, ttl, rdata):
        """
        Insert a value into the cache.
        """
        key = (qtype, qclass)
        
        if not name in self.cache:
            self.cache[name] = {}
        
        self.cache[name][key] = time.time() + ttl, ttl, rdata
    
    def update_cached(self, name, qtype, qclass, ttl, rdata):
        """
        Update a value in the cache.
        """
        cached = self.get_cached(name, qtype, qclass)
        if cached:
            ttl = min(ttl, cached[0])
            if cached[1] and rdata:
                for v in cached[1]:
                    if not v in rdata:
                        rdata.append(v)
            elif cached[1]:
                rdata = cached[1]
        
        self._set_cached(name, qtype, qclass, ttl, rdata)
    
    ##### Message Handling #####################################################
    
    def send_message(self, message, callback=None, timeout=15):
        """
        Send an instance of DNSMessage to a DNS server and call the provided
        callback when a response is received, or if the action times out.
        
        =========  =========  ============
        Argument   Default    Description
        =========  =========  ============
        message               The :class:`DNSMessage` instance to send to the server.
        callback   ``None``   *Optional.* A function to call when a response for the query has been received, or when the query has timed out.
        timeout    ``15``     *Optional.* How long, in seconds, to wait before timing out.
        =========  =========  ============
        """
        start_id = self._last_id if self._last_id >= 0 else 65535
        while message.id is None or message.id in self._messages:
            self._last_id += 1
            if self._last_id > 65535:
                self._last_id = 0
            if self._last_id == start_id:
                raise Exception("Too many pending DNS queries.")
            message.id = self._last_id
        
        # Timeout in timeout seconds.
        df_timeout = pants.engine.defer(timeout, self._msg_timeout, message.id)
        serv_timeout = pants.engine.defer(2, self._msg_next_server, message.id)
        
        # Build the message string and store info about it in our dict.
        msg = str(message)
        self._messages[message.id] = [callback, msg, message, df_timeout,
                                      serv_timeout, self.servers[0]]
        
        # Make sure we have a socket, then send the message.
        if not self._socket:
            self._initialize_udp()
        
        self._socket.write(msg, (self.servers[0], DNS_PORT))
        
    def _msg_timeout(self, id):
        """ Act upon a timed-out query. """
        if not id in self._messages:
            return
        
        callback, msg, message, df_timeout, serv_timeout, last_server = self._messages[id]
        del self._messages[id]
        
        # Clear the remaining timeout.
        serv_timeout()
        
        if callback:
            self._safely_call(callback, DNS_TIMEOUT, None)
    
    def _msg_next_server(self, id):
        """ Rotate servers. """
        if not id in self._messages:
            return
        
        message = self._messages[id]
        if message[-1] == self.servers[0]:
            # Cycle the list since it hasn't been modified yet.
            self.servers.append(self.servers.pop(0))
        
        # Make a new deferred, cancelling the old one.
        message[4]()
        message[4] = pants.engine.defer(4, self._msg_next_server, id)
        
        # Send the message to the new server.
        self._socket.write(message[1], (self.servers[0], DNS_PORT))
    
    def receive_message(self, data):
        if not isinstance(data, DNSMessage):
            try:
                data = DNSMessage.from_string(data)
            except TooShortError:
                if len(data) < 2:
                    return
                
                id = struct.unpack("!H", data[:2])
                if not id in self._messages:
                    return
                
                # Rotate servers, since that one gave a bad response.
                self._msg_next_server(id)
                return
        
        if not data.id in self._messages:
            return
        
        callback, msg, message, df_timeout, serv_timeout, last_server = self._messages[data.id]
        del self._messages[data.id]
        
        if not data.server:
            if self._socket and isinstance(self._socket.remote_addr, tuple):
                data.server = '%s:%d' % self._socket.remote_addr
            else:
                data.server = '%s:%d' % (last_server, DNS_PORT)
        
        # Cancel the timeouts.
        df_timeout()
        serv_timeout()
        
        # Call our callback.
        if callback:
            self._safely_call(callback, DNS_OK, data)
    
    ##### Query Sending ########################################################
    
    def query(self, name, qtypes=(A,), qclass=IN, callback=None, timeout=15, use_cache=True, use_hosts=True):
        """
        Make a DNS query for the given name, for records with the given qtypes
        and qclass.
        
        ==========  ==========  ============
        Argument    Default     Description
        ==========  ==========  ============
        name                    The name to query.
        qtypes      ``(A, )``   *Optional.* A list of QTYPES to query.
        qclass      ``IN``      *Optional.* The QCLASS to query.
        callback    ``None``    *Optional.* A function to call when a response for the query has been received, or when the query has timed out.
        timeout     ``15``      *Optional.* The time, in seconds, to wait before timing out.
        use_cache   ``True``    *Optional.* Whether or not to use the cache.
        use_hosts   ``True``    *Optional.* Whether or not to use the operating system's hosts file.
        ==========  ==========  ============
        """
        lname = name.lower()
        results = []
        
        if use_hosts:
            # Hosts are preferred over everything else, so if even one qtype is
            # present, just return that.
            if host_time + 30 < time.time():
                load_hosts()
            
            
            for qt in qtypes:
                if qt in hosts and lname in hosts[qt]:
                    results.append(hosts[qt][lname])
            
            if results:
                if callback:
                    self._safely_call(callback, DNS_OK, None, None, results)
                return
        
        # Build a list we can alter.
        wanted = list(qtypes)
        shortest_ttl = 1000000
        
        if use_cache:
            # Attempt to use as many cached values as we can.
            for qt in qtypes:
                cached = self.get_cached(lname, qt, qclass)
                if cached:
                    shortest_ttl = min(cached[0], shortest_ttl)
                    if cached[1]:
                        results.append(cached[1])
                    wanted.remove(qt)
        
        # Try getting a cname.
        cached = self.get_cached(lname, CNAME, qclass)
        if cached:
            cname = cached[1]
        else:
            cname = None
        
        # Do we have all the results we need?
        if not wanted:
            if callback:
                self._safely_call(callback, DNS_OK, cname, shortest_ttl, results)
            return
        
        # Make a list for this particular query.
        q = [name, qtypes, qclass, callback, timeout, use_cache, use_hosts, results, wanted, shortest_ttl, cname, DNS_OK]
        
        # Queue a timeout.
        df_timeout = pants.engine.defer(timeout, self._query_timeout, q)
        
        # Create the function for handling responses.
        def handle_response(rstatus, response):
            if rstatus > q[-1]:
                q[-1] = rstatus
            
            if not response:
                return
            
            # If it's a name error, we can end right now.
            if response.rcode == DNS_NAMEERROR:
                df_timeout()
                if callback:
                    self._safely_call(callback, DNS_NAMEERROR, None, None, None)
                return
            
            # Read all of the answers into a dict.
            answers = {}
            
            for (aname, atype, aclass, attl, ardata) in response.answers:
                if not aclass == qclass:
                    continue
                
                if not atype in answers:
                    answers[atype] = []
                
                if len(ardata) == 1:
                    answers[atype].append(ardata[0])
                    if use_cache:
                        self.update_cached(lname, atype, aclass, attl, [ardata[0]])
                elif isinstance(ardata, tuple) and hasattr(ardata, '_fields'):
                    answers[atype].append(ardata)
                    if use_cache:
                        self.update_cached(lname, atype, aclass, attl, [ardata])
                else:
                    answers[atype].extend(ardata)
                    if use_cache:
                        self.update_cached(lname, atype, aclass, attl, list(ardata))
                
                if atype in wanted:
                    if not attl:
                        attl = 30
                    q[-3] = min(q[-3], attl)
            
            for (aname, atype, aclass) in response.questions:
                if not aclass == qclass or atype in answers:
                    continue
                if atype in wanted:
                    wanted.remove(atype)
            
            if CNAME in answers:
                q[-2] = answers[CNAME][0]
            
            for qt in wanted[:]:
                if qt in answers:
                    results.extend(answers[qt])
                    wanted.remove(qt)
            
            if not wanted:
                # Make sure we don't timeout at this point.
                df_timeout()
                
                if callback:
                    if results:
                        q[-1] = DNS_OK
                    self._safely_call(callback, q[-1], q[-2], q[-3], results)
                return
        
        # Send all the queries now.
        for qt in wanted:
            m = DNSMessage()
            m.questions.append((name, qt, qclass))
            self.send_message(m, handle_response)
    
    def _query_timeout(self, query):
        """ Handle a query timing out. """
        (name, qtypes, qclass, callback, timeout, use_cache, use_hosts, results,
        wanted, ttl, cname, status) = query
        
        if not callback:
            return

        if results:
            status = DNS_OK
            self._safely_call(callback, status, cname, ttl, results)
        else:
            if status == 0:
                status = DNS_TIMEOUT
            self._safely_call(callback, status, cname, ttl, None)

resolver = Resolver()

###############################################################################
# Helper Functions
###############################################################################

query = resolver.query
send_message = resolver.send_message

def gethostbyaddr(ip_address, callback, timeout=10):
    """
    Returns a tuple ``(hostname, aliaslist, ipaddrlist)``, functioning similarly
    to :func:`socket.gethostbyaddr`. When the information is available, it will
    be passed to callback. If the attempt fails, the callback will be called
    with None instead.

    ===========  ========  ============
    Argument     Default   Description
    ===========  ========  ============
    ip_address             The IP address to look up information on.
    callback               The function to call when a result is available.
    timeout      10        *Optional.* How long, in seconds, to wait before timing out.
    ===========  ========  ============
    """
    is_ipv6 = False
    if hasattr(socket, 'inet_pton'):
        try:
            addr = socket.inet_pton(socket.AF_INET6, ip_address)
            is_ipv6 = True
        except socket.error:
            try:
                addr = socket.inet_pton(socket.AF_INET, ip_address)
            except socket.error:
                raise ValueError("%r is not a valid IP address." % ip_address)
    else:
        try:
            addr = socket.inet_aton(ip_address)
        except socket.error:
            is_ipv6 = True

    if is_ipv6:
        if not hasattr(socket, 'inet_pton'):
            raise ImportError("socket lacks inet_pton.")
        addr = socket.inet_pton(socket.AF_INET6, ip_address)

        name = ''.join('%02x' % ord(c) for c in addr)
        name = '.'.join(reversed(name)) + '.ip6.arpa'

    else:
        name = '.'.join(reversed(ip_address.split('.'))) + '.in-addr.arpa'


    def handle_response(status, cname, ttl, rdata):
        if status != DNS_OK:
            res = None
        else:
            if not rdata:
                res = None
            else:
                res = rdata[0], [name] + list(rdata[1:]), [ip_address]

        try:
            callback(res)
        except Exception:
            log.exception('Error calling callback for gethostbyaddr.')

    resolver.query(name, qtypes=(PTR,), callback=handle_response, timeout=timeout)

def gethostbyname(hostname, callback, timeout=10):
    """
    Translate a host name to an IPv4 address, functioning similarly to
    :func:`socket.gethostbyname`. When the information becomes available, it
    will be passed to callback. If the underlying query fails, the callback
    will be called with None instead.

    =========  ========  ============
    Argument   Default   Description
    =========  ========  ============
    hostname             The hostname to look up information on.
    callback             The function to call when a result is available.
    timeout    10        *Optional.* How long, in seconds, to wait before timing out.
    =========  ========  ============
    """
    def handle_response(status, cname, ttl, rdata):
        if status != DNS_OK or not rdata:
            res = None
        else:
            res = rdata[0]

        try:
            callback(res)
        except Exception:
            log.exception('Error calling callback for gethostbyname.')

    resolver.query(hostname, qtypes=(A,), callback=handle_response, timeout=timeout)

def gethostbyname_ex(hostname, callback, timeout=10):
    """
    Translate a host name to an IPv4 address, functioning similarly to
    :func:`socket.gethostbyname_ex` and return a tuple
    ``(hostname, aliaslist, ipaddrlist)``. When the information becomes
    available, it will be passed to callback. If the underlying query fails,
    the callback will be called with None instead.

    =========  ========  ============
    Argument   Default   Description
    =========  ========  ============
    hostname             The hostname to look up information on.
    callback             The function to call when a result is available.
    timeout    10        *Optional.* How long, in seconds, to wait before timing out.
    =========  ========  ============
    """
    def handle_response(status, cname, ttl, rdata):
        if status != DNS_OK or not rdata:
            res = None
        else:
            if cname != hostname:
                res = cname, [hostname], list(rdata)
            else:
                res = cname, [], list(rdata)

        try:
            callback(res)
        except Exception:
            log.exception('Error calling callback for gethostbyname_ex.')

    resolver.query(hostname, qtypes=(A,), callback=handle_response, timeout=timeout)

###############################################################################
# Synchronous Support
###############################################################################

class Synchroniser(object):
    __slots__ = ('_parent',)

    def __init__(self, parent):
        self._parent = parent

    def __getattr__(self, key):
        if key.startswith('_'):
            return object.__getattribute__(self, key)

        func = self._parent[key]

        if not callable(func):
            raise ValueError("%r isn't callable." % key)

        def doer(*a, **kw):
            if pants.engine._running:
                raise RuntimeError("synchronous calls cannot be made while Pants is already running.")

            data = []

            def callback(*a,**kw):
                if kw:
                    if a:
                        a = a + (kw, )
                    else:
                        a = kw

                if isinstance(a, tuple) and len(a) == 1:
                    a = a[0]

                data.append(a)
                pants.engine.stop()

            kw['callback'] = callback
            func(*a, **kw)
            pants.engine.start()
            return data[0]

        doer.__name__ = func.__name__

        return doer

sync = synchronous = Synchroniser(globals())
