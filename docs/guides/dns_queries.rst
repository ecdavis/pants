DNS Queries
***********

Pants provides a `DNS <http://en.wikipedia.org/wiki/Domain_Name_System>`_
client as part of its core for performing non-blocking queries, allowing for
the easy resolution of domain names without an impact on performance. It
provides an asynchronous :class:`Reactor` that automatically discovers DNS
servers where possible and performs queries using the :class:`~pants.datagram.Datagram`
class.

Basic Queries
=============

When it's imported, the ``pants.util.dns`` module automatically creates an
instance of the :class:`~pants.util.dns.Resolver` class, and makes that
instance's copies of :func:`~pants.util.dns.Resolver.query` and
:func:`~pants.util.dns.Resolver.send_message` available as
``pants.util.dns.query`` and ``pants.util.dns.send_message`` respectively.

``pants.util.dns.query`` can be used to query a DNS server, and automatically
handles caching and parsing any ``RDATA`` for you (for most common query types).
When using :func:`~pants.util.dns.Resolver.query`, you're expected (though not
required) to provide a callback function that will be called when a response
has been received, or the request has timed out. The callback function must
accept the parameters: ``status, cname, ttl, rdata``. For example::
    
    >>> from pants.util import dns
    >>> from pants import engine
    >>> def response_handler(status, cname, ttl, rdata):
    ...     print status == dns.DNS_OK
    ...     print cname
    ...     print ttl
    ...     print repr(rdata)
    ...     
    ...     engine.stop()
    ... 
    >>> dns.query('localhost', callback=response_handler)
    >>> engine.start()
    True
    None
    0
    ('127.0.0.1',)

``status`` will equal ``DNS_OK``, which has a value of 0, if everything goes
smoothly. Values other than 0 indicate an error.

Synchronous Testing
===================

To facilitate testing, the DNS module provides an object that makes queries
effectively synchronous. It does so by starting the engine once called, with a
special callback function that stops the engine again and stores the result
where it may be returned.

To use, simply run ``pants.util.dns.sync.query``. :func:`~pants.util.dns.gethostbyaddr`,
:func:`~pants.util.dns.gethostbyname`, and :func:`~pants.util.dns.gethostbyname_ex` all
work with ``pants.util.dns.sync`` as well. Example::
    
    >>> from pants.util import dns
    >>> dns.sync.query('localhost')
    (0, None, None, ('127.0.0.1',))

``RDATA`` Formatting
====================

RDATA is, of course, the most important part of the response. The Resolver
will attempt to automatically parse received RDATA if it knows how to deal with
RDATA for the query type. The parsed RDATA is returned as an instance of a
:func:`collections.namedtuple` for convenience.

The following formats are handled automatically:

**A**:
    >>> dns.sync.query('www.google.com', dns.A)
    (0, 'www.l.google.com', 31, ('74.125.225.82', '74.125.225.81', '74.125.225.80', '74.125.225.84', '74.125.225.83'))

**AAAA**:
    >>> dns.sync.query('ipv6.google.com', dns.AAAA)
    (0, 'ipv6.l.google.com', 299, ('2001:4860:800b::67',))

**CNAME**:
    >>> dns.sync.query('www.google.com', dns.CNAME)
    (0, 'www.l.google.com', 602242, ('www.l.google.com',))

**DNAME**

**DNSKEY**

**HINFO**

**MB**

**MD**

**MF**

**MG**

**MINFO**

**MR**

**MX**:
    >>> dns.sync.query('google.com', dns.MX)
    (0, None, 600, (MX_Record(preference=10, name='aspmx.l.google.com'), MX_Record(preference=40, name='alt3.aspmx.l.google.com'), MX_Record(preference=50, name='alt4.aspmx.l.google.com'), MX_Record(preference=30, name='alt2.aspmx.l.google.com'), MX_Record(preference=20, name='alt1.aspmx.l.google.com')))

**NS**:
    >>> dns.sync.query('google.com', dns.NS)
    (0, None, 337913, ('ns3.google.com', 'ns4.google.com', 'ns1.google.com', 'ns2.google.com'))

**NULL**

**PTR**:
    >>> dns.sync.query('8.8.8.8.in-addr.arpa', dns.PTR)
    (0, None, 86400, ('google-public-dns-a.google.com',))

**RP**

**SOA**:
    >>> dns.sync.query('google.com', dns.SOA)
    (0, None, 86359, (SOA_Record(mname='ns1.google.com', rname='dns-admin.google.com', serial=1451784, refresh=7200, retry=1800, expire=1209600, minimum=300),))

**SRV**

**TXT**:
    >>> dns.sync.query('google.com', dns.TXT)
    (0, None, 2958, ('v=spf1 include:_netblocks.google.com ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all',))

**WKS**
