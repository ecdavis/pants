###############################################################################
#
# Copyright 2011-2012 Pants Developers (see AUTHORS.txt)
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
import itertools
import os
import random
import socket
import struct
import sys
import time

from pants.engine import Engine
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
# _DNSStream Class
###############################################################################

class _DNSStream(Stream):
    """
    A subclass of Stream that makes things way easier inside Resolver.
    """
    def __init__(self, resolver, id, **kwargs):
        Stream.__init__(self, **kwargs)
        self.resolver = resolver
        self.id = id

        self.response = ''

    def on_connect(self):
        if not self.id in self.resolver._messages:
            if self.id in self.resolver._tcp:
                del self.resolver._tcp[self.id]
            self.close()
            return

        message = str(self.resolver._messages[self.id][1])
        self._wait_for_write_event = True
        self.write(message)

    def on_read(self, data):
        if not self.id in self.resolver._messages:
            if self.id in self.resolver._tcp:
                del self.resolver._tcp[self.id]
            self.close()
            return

        self.response += data

        try:
            m = DNSMessage.from_string(self.response)
        except TooShortError:
            return

        if self.remote_address and isinstance(self.remote_address, tuple):
            m.server = '%s:%d' % self.remote_address

        if self.id in self.resolver._tcp:
            del self.resolver._tcp[self.id]
        self.close()

        self.resolver.receive_message(m)

###############################################################################
# Resolver Class
###############################################################################

class Resolver(object):
    """
    The Resolver class generates DNS messages, sends them to remote servers,
    and processes any responses. The bulk of the heavy lifting is done in
    DNSMessage and the RDATA handling functions, however.

    =========  ============
    Argument   Description
    =========  ============
    servers    *Optional.* A list of DNS servers to query. If a list isn't provided, Pants will attempt to retrieve a list of servers from the OS, falling back to a list of default servers if none are available.
    engine     *Optional.* The :class:`pants.engine.Engine` instance to use.
    =========  ============
    """
    def __init__(self, servers=None, engine=None):
        self.servers = servers or list_dns_servers()
        self.engine = engine or Engine.instance()

        # Internal State
        self._messages = {}
        self._cache = {}
        self._queries = {}
        self._tcp = {}
        self._udp = None
        self._last_id = -1

    def _safely_call(self, callback, *args, **kwargs):
        try:
            callback(*args, **kwargs)
        except Exception:
            log.exception('Error calling callback for DNS result.')

    def _error(self, message, err=DNS_TIMEOUT):
        if not message in self._messages:
            return

        if message in self._tcp:
            try:
                self._tcp[message].close()
            except Exception:
                pass
            del self._tcp[message]

        callback, message, df_timeout, media, data = self._messages[message]
        del self._messages[message.id]

        try:
            df_timeout.cancel()
        except Exception:
            pass

        if err == DNS_TIMEOUT and data:
            self._safely_call(callback, DNS_OK, data)
        else:
            self._safely_call(callback, err, None)

    def _init_udp(self):
        """
        Create a new Datagram instance and listen on a socket.
        """
        self._udp = Datagram(engine=self.engine)
        self._udp.on_read = self.receive_message

        start = port = random.randrange(10005, 65535)
        while True:
            try:
                self._udp.listen(('',port))
                break
            except Exception:
                port += 1
                if port > 65535:
                    port = 10000
                if port == start:
                    raise Exception("Can't listen on any port.")

    def send_message(self, message, callback=None, timeout=10, media=None):
        """
        Send an instance of DNSMessage to a DNS server, and call the provided
        callback when a response is received, or if the action times out.

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        message              The :class:`DNSMessage` instance to send to the server.
        callback   None      *Optional.* The function to call once the response has been received or the attempt has timed out.
        timeout    10        *Optional.* How long, in seconds, to wait before timing out.
        media      None      *Optional.* Whether to use UDP or TCP. UDP is used by default.
        =========  ========  ============
        """
        while message.id is None or message.id in self._messages:
            self._last_id += 1
            if self._last_id > 65535:
                self._last_id = 0
            message.id = self._last_id

        # Timeout in timeout seconds.
        df_timeout = self.engine.defer(timeout, self._error, message.id)

        # Send the Message
        msg = str(message)
        if media is None:
            media = 'udp'
            #if len(msg) > 512:
            #    media = 'tcp'
            #else:
            #    media = 'udp'

        # Store Info
        self._messages[message.id] = callback, message, df_timeout, media, None

        if media == 'udp':
            if self._udp is None:
                self._init_udp()
            try:
                self._udp.write(msg, (self.servers[0], DNS_PORT))
            except Exception:
                # Pants gummed up. Try again.
                self._next_server(message.id)

            self.engine.defer(0.5, self._next_server, message.id)

        else:
            tcp = self._tcp[message.id] = _DNSStream(self, message.id)
            tcp.connect((self.servers[0], DNS_PORT))

    def _next_server(self, id):
        if not id in self._messages or id in self._tcp:
            return

        # Cycle the list.
        self.servers.append(self.servers.pop(0))

        msg = str(self._messages[id][1])
        try:
            self._udp.write(msg, (self.servers[0], DNS_PORT))
        except Exception:
            try:
                self._udp.close()
            except Exception:
                pass
            del self._udp
            self._init_udp()
            self._udp.write(msg, (self.servers[0], DNS_PORT))

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

                self._error(id, err=DNS_FORMATERROR)
                return

        if not data.id in self._messages:
            return

        callback, message, df_timeout, media, _ = self._messages[data.id]

        #if data.tc and media == 'udp':
        #    self._messages[data.id] = callback, message, df_timeout, 'tcp', data
        #    tcp = self._tcp[data.id] = _DNSStream(self, message.id)
        #    tcp.connect((self.servers[0], DNS_PORT))
        #    return

        if not data.server:
            if self._udp and isinstance(self._udp.remote_address, tuple):
                data.server = '%s:%d' % self._udp.remote_address
            else:
                data.server = '%s:%d' % (self.servers[0], DNS_PORT)

        try:
            df_timeout.cancel()
        except Exception:
            pass

        del self._messages[data.id]
        self._safely_call(callback, DNS_OK, data)

    def query(self, name, qtype=A, qclass=IN, callback=None, timeout=10, allow_cache=True, allow_hosts=True):
        """
        Make a DNS request of the given QTYPE for the given name.

        ============  ========  ============
        Argument      Default   Description
        ============  ========  ============
        name                    The name to query.
        qtype         A         *Optional.* The QTYPE to query.
        qclass        IN        *Optional.* The QCLASS to query.
        callback      None      *Optional.* The function to call when a response for the query has been received, or when the request has timed out.
        timeout       10        *Optional.* The time, in seconds, to wait before timing out.
        allow_cache   True      *Optional.* Whether or not to use the cache. If you expect to be performing thousands of requests, you may want to disable the cache to avoid excess memory usage.
        allow_hosts   True      *Optional.* Whether or not to use any records gathered from the OS hosts file.
        ============  ========  ============
        """
        if not isinstance(qtype, (list,tuple)):
            qtype = (qtype, )

        if allow_hosts:
            if host_time + 30 < time.time():
                load_hosts()

            cname = None
            if name in self._cache and CNAME in self._cache[name]:
                cname = self._cache[name][CNAME]

            result = []

            if AAAA in qtype and name in hosts[AAAA]:
                result.append(hosts[AAAA][name])

            if A in qtype and name in hosts[A]:
                result.append(hosts[A][name])

            if result:
                if callback:
                    self._safely_call(callback, DNS_OK, cname, None, tuple(result))
                return

        if allow_cache and name in self._cache:
            cname = self._cache[name].get(CNAME, None)

            tm = time.time()
            result = []
            min_ttl = sys.maxint

            for t in qtype:
                death, ttl, rdata = self._cache[name][(t, qclass)]
                if death < tm:
                    del self._cache[name][(t, qclass)]
                    continue

                min_ttl = min(ttl, min_ttl)
                if rdata:
                    result.extend(rdata)

            if callback:
                self._safely_call(callback, DNS_OK, cname, min_ttl,
                                    tuple(result))
            return

        # Build a message and add our question.
        m = DNSMessage()

        m.questions.append((name, qtype[0], qclass))

        # Make the function for handling our response.
        def handle_response(status, data):
            cname = None
            # TTL is 30 by default, so answers with no records we want will be
            # repeated, but not too often.
            ttl = sys.maxint

            if not data:
                self._safely_call(callback, status, None, None, None)
                return

            rdata = {}
            final_rdata = []
            for (aname, atype, aclass, attl, ardata) in data.answers:
                if atype == CNAME:
                    cname = ardata[0]

                if atype in qtype and aclass == qclass:
                    ttl = min(attl, ttl)
                    if len(ardata) == 1:
                        rdata.setdefault(atype, []).append(ardata[0])
                        final_rdata.append(ardata[0])
                    else:
                        rdata.setdefault(atype, []).append(ardata)
                        final_rdata.append(ardata)
            final_rdata = tuple(final_rdata)
            ttl = min(30, ttl)

            if allow_cache:
                if not name in self._cache:
                    self._cache[name] = {}
                    if cname:
                        self._cache[name][CNAME] = cname
                    for t in qtype:
                        self._cache[name][(t, qclass)] = time.time() + ttl, ttl, rdata.get(t, [])

            if data.rcode != DNS_OK:
                status = data.rcode

            self._safely_call(callback, status, cname, ttl, final_rdata)

        # Send it, so we get an ID.
        self.send_message(m, handle_response)

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

    resolver.query(name, qtype=PTR, callback=handle_response, timeout=timeout)

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

    resolver.query(hostname, qtype=A, callback=handle_response, timeout=timeout)

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

    resolver.query(hostname, qtype=A, callback=handle_response, timeout=timeout)

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
            if Engine.instance()._running:
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
                Engine.instance().stop()

            kw['callback'] = callback
            func(*a, **kw)
            Engine.instance().start()
            return data[0]

        doer.__name__ = func.__name__

        return doer

sync = synchronous = Synchroniser(globals())
