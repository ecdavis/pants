#!/usr/bin/env python
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

###############################################################################
# Imports
###############################################################################

import optparse
import sys

from pants.util.dns import *

###############################################################################
# Main
###############################################################################

if __name__ == '__main__':
    usage = "usage: %prog [options] name [qtype]"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                help="Show extra messages.")
    parser.add_option("--servers", dest="list", action="store_true", default=False,
                help="List the discovered DNS servers.")
    parser.add_option("--hosts", dest="lh", action="store_true", default=False,
                help="List the entries loaded from the OS hosts file.")

    options, args = parser.parse_args()

    if options.debug:
        logging.getLogger('').setLevel(logging.DEBUG)
        logging.info('...')

    if options.list:
        print ''
        print 'Available DNS Servers'
        for i in list_dns_servers():
            print ' %s' % i

    if options.lh:
        print ''
        print 'Using: %s' % host_path

        print ''
        print 'Detected IPv4 Hosts'
        for k,v in hosts[A].iteritems():
            print ' %-40s A     %s' % (k, v)

        print ''
        print 'Detected IPv6 Hosts'
        for k,v in hosts[AAAA].iteritems():
            print ' %-40s AAAA  %s' % (k, v)

    if sys.platform == 'win32':
        timer = time.clock
    else:
        timer = time.time

    args = list(args)
    while args:
        host = args.pop(0)
        if args:
            qt = args.pop(0)
        else:
            qt = 'A'
        
        qtype = []
        for t in qt.split(','):
            t = t.upper()
            if t in QTYPES:
                t = QTYPES.index(t) + 1
            else:
                try:
                    t = int(t)
                except ValueError:
                    print 'Invalid QTYPE, %r.' % t
                    sys.exit(1)
            qtype.append(t)
        qtype = tuple(qtype)

        # Build a Message
        m = DNSMessage()
        
        for t in qtype:
            m.questions.append((host, t, IN))

        print ''

        # Query it.
        start = timer()
        status, data = sync.send_message(m)
        end = timer()

        if data and data.rcode != DNS_OK:
            status = data.rcode

        if qtype == A and host in hosts[A]:
            print "A record for %r in hosts: %s" % (host, hosts[A][host])
            print ""
        elif qtype == AAAA and host in hosts[AAAA]:
            print "AAAA record for %r in hosts: %s" % (host, hosts[AAAA][host])
            print ""

        if status == DNS_OK:
            print "Response: DNS_OK (%d)" % status
        elif status == DNS_TIMEOUT:
            print "Response: DNS_TIMEOUT (%d)" % status
        elif status == DNS_FORMATERROR:
            print "Response: DNS_FORMATERROR (%d)" % status
        elif status == DNS_SERVERFAILURE:
            print "Response: DNS_SERVERFAILURE (%d)" % status
        elif status == DNS_NAMEERROR:
            print "Response: DNS_NAMEERROR (%d)" % status
        elif status == DNS_NOTIMPLEMENTED:
            print "Response: DNS_NOTIMPLEMENTED (%d)" % status
        elif status == DNS_REFUSED:
            print "Response: DNS_REFUSED (%d)" % status
        else:
            print "Response: UNKNOWN (%d)" % status

        if not data:
            if status == DNS_OK:
                print "Empty response, but OK status? Something's wrong."
            else:
                print "Empty response."
            continue

        opcode = 'UNKNOWN (%d)' % data.opcode
        if data.opcode == OP_QUERY:
            opcode = 'QUERY'
        elif data.opcode == OP_IQUERY:
            opcode = 'IQUERY'
        elif data.opcode == OP_STATUS:
            opcode = 'STATUS'

        rcode = data.rcode
        if rcode == 0:
            rcode = 'OK'
        elif rcode == 1:
            rcode = 'Format Error'
        elif rcode == 2:
            rcode = 'Server Failure'
        elif rcode == 3:
            rcode = 'Name Error'
        elif rcode == 4:
            rcode = 'Not Implemented'
        elif rcode == 5:
            rcode = 'Refused'
        else:
            rcode = 'Unknown (%d)' % rcode

        flags = []
        if data.qr: flags.append('qr')
        if data.aa: flags.append('aa')
        if data.tc: flags.append('tc')
        if data.rd: flags.append('rd')
        if data.ra: flags.append('ra')

        print 'opcode: %s; rcode: %s; id: %d; flags: %s' % (opcode, rcode, data.id, ' '.join(flags))
        print 'queries: %d; answers: %d; authorities: %d; additional: %d' % (len(data.questions), len(data.answers), len(data.authrecords), len(data.additional))

        print ''
        print 'Question Section'
        for name, qtype, qclass in data.questions:
            if qtype < len(QTYPES):
                qtype = QTYPES[qtype-1]
            else:
                qtype = str(qtype)

            if qclass == IN:
                qclass = 'IN'
            else:
                qclass = str(qclass)

            print ' %-31s %-5s %s' % (name, qclass, qtype)

        for lbl,lst in (('Answer', data.answers), ('Authority', data.authrecords), ('Additional', data.additional)):
            if not lst:
                continue
            print ''
            print '%s Section' % lbl
            for name, atype, aclass, ttl, rdata in lst:
                if atype < len(QTYPES):
                    atype = QTYPES[atype-1]
                else:
                    atype = str(atype)

                if aclass == IN:
                    aclass = 'IN'
                else:
                    aclass = str(aclass)

                print ' %-22s %-8d %-5s %-8s %s' % (name, ttl, aclass, atype, ' '.join(str(x) for x in rdata))

        print ''
        print 'Query Time: %d msec' % int((end - start) * 1000)
        print 'Server: %s' % str(data.server)
        print 'Message Size: %d' % len(str(data))

    print ''