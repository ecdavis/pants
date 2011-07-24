DNS
***

Pants provides a `DNS <http://en.wikipedia.org/wiki/Domain_Name_System>`_
client as part of its core for performing non-blocking queries, allowing for
the easy resolution of domain names without an impact on performance. It
provides an asynchronous :class:`Reactor` that automatically discovers DNS
servers where possible and performs queries using the :class:`~pants.datagram.Datagram`
class.

Basic Queries
-------------

When it's imported, the ``pants.dns`` module automatically creates an instance
of the :class:`~pants.dns.Resolver` class, and makes that instance's copies
of :func:`~pants.dns.Resolver.query` and :func:`~pants.dns.Resolver.send_message`
available as ``pants.dns.query`` and ``pants.dns.send_message`` respectively.

``pants.dns.query`` can be used to query a DNS server, and automatically handles
caching and parsing any ``RDATA`` for you (for most common query types). When
using :func:`~pants.dns.Resolver.query`, you're expected (though not required)
to provide a callback function that will be called when a response has been
received, or the request has timed out. The callback function must accept the
parameters: ``status, cname, ttl, rdata``. For example::
    
    >>> from pants import dns, engine
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
-------------------

To facilitate testing, the DNS module provides an object that makes queries
effectively synchronous. It does so by starting the engine once called, with a
special callback function that stops the engine again and stores the result
where it may be returned.

To use, simply run ``pants.dns.sync.query``. :func:`~pants.dns.gethostbyaddr`,
:func:`~pants.dns.gethostbyname`, and :func:`~pants.dns.gethostbyname_ex` all
work with ``pants.dns.sync`` as well. Example::
    
    >>> from pants import dns
    >>> dns.sync.query('localhost')
    (0, None, None, ('127.0.0.1',))

``RDATA`` Formatting
--------------------

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

DNS Testing
-----------

A DNS testing tool is provided as ``pants.util.dns``, that uses ``pants.dns``
to query DNS servers. This tool can be used to determine whether or not Pants
is loading your OS's hosts file, and what DNS servers Pants is attempting to
use.

The utility is most easilly used via Python's ability to run a module as a
script::
    
    $ python -m pants.util.dns

To perform a query, simply enter the name you wish to query, a space, and then
the record type. Example::
    
    $ python -m pants.util.dns www.google.com A

This will generate output similar to that of the ``dig`` command. To list the
DNS servers that Pants is using, enter::
    
    $ python -m pants.util.dns --servers

To list the static hosts listed from the OS's hosts file, enter::
    
    $ python -m pants.util.dns --hosts

API
---

Constants
=========

:Status Codes:
    ===================  ======
    Constant             Value
    ===================  ======
    DNS_TIMEOUT          -1
    DNS_OK               0
    DNS_FORMATERROR      1
    DNS_SERVERFAILURE    2
    DNS_NAMEERROR        3
    DNS_NOTIMPLEMENTED   4
    DNS_REFUSED          5
    ===================  ======

:Query Types:
    ===========  ======
    Constant
    ===========  ======
    A            1
    NS           2
    MD           3
    MF           4
    CNAME        5
    SOA          6
    MB           7
    MG           8
    MR           9
    NULL         10
    WKS          11
    PTR          12
    HINFO        13
    MINFO        14
    MX           15
    TXT          16
    RP           17
    AFSDB        18
    X25          19
    ISDN         20
    RT           21
    NSAP         22
    NSAP_PTR     23
    SIG          24
    KEY          25
    PX           26
    GPOS         27
    AAAA         28
    LOC          29
    NXT          30
    EID          31
    NIMLOC       32
    SRV          33
    ATMA         34
    NAPTR        35
    KX           36
    CERT         37
    A6           38
    DNAME        39
    SINK         40
    OPT          41
    APL          42
    DS           43
    SSHFP        44
    IPSECKEY     45
    RRSIG        46
    NSEC         47
    DNSKEY       48
    DHCID        49
    NSEC3        50
    NSEC3PARAM   51
    ===========  ======

:OPCODEs:
    ===========  ======
    Constant     Value
    ===========  ======
    OP_QUERY     0
    OP_IQUERY    1
    OP_STATUS    2
    ===========  ======

:Query Classes:
    =========  ======
    Constant   Value
    =========  ======
    IN         1
    =========  ======

Functions
=========

.. autofunction:: pants.dns.gethostbyaddr
.. autofunction:: pants.dns.gethostbyname
.. autofunction:: pants.dns.gethostbyname_ex

Classes
=======

.. autoclass:: pants.dns.Resolver
    :members: query, send_message

.. autoclass:: pants.dns.DNSMessage
    :members: to_string, from_string
