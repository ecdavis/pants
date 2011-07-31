``pants.util.dns``
******************

.. automodule:: pants.util.dns


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

.. autofunction:: gethostbyaddr

.. autofunction:: gethostbyname

.. autofunction:: gethostbyname_ex


Classes
=======

.. autoclass:: Resolver
    :members: query, send_message

.. autoclass:: DNSMessage
    :members: to_string, from_string
