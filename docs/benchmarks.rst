Benchmarks
**********

Benchmarking high-speed network servers is a difficult task but an extremely
useful one. Good benchmarks not only reveal performance characteristics, they
also effectively test the server and help to reveal unusual behaviour. The
benchmarks that have been run on Pants to date have been limited, but should
provide a useful measure of its performance for highly-responsive,
low-throughput servers.

Benchmarks such as this are only useful when they truly give an accurate picture
of the performance of the frameworks involved. We have tried our best to
benchmark these frameworks in an accurate and fair manner. If you find an error
in our methodology, please do let us know by contacting us directly or filing
an issue on the `pants-bench repository on GitHub
<https://github.com/ecdavis/pants-bench>`_. All feedback and suggestions for
improvement is greatly appreciated.


Setup
=====

Hardware
--------

The benchmarks in this document were run using two machines on a closed LAN.

* **Server**: Mac Mini MC815X - 2.3GHz dual-core Intel Core i5-2415M, 2GB
  1333MHz DDR3 SDRAM.
* **Client**: Macbook Pro MC700X - 2.30GHz dual-core Intel Core i5-2415M, 4GB
  1333MHz DDR3 SDRAM.

Software
--------

A number of frameworks were tested in this benchmark. The programs used for the
various servers can be found in the `pants-bench repository on GitHub
<https://github.com/ecdavis/pants-bench/tree/3bebe654675f1cd61cfb4e258dd2147b22da4597>`_.

The client used the `siege benchmarking tool
<http://www.joedog.org/index/siege-home>`_ to generate load on the server. The
siege configuration file used for these benchmarks can also be found in the
`pants-bench repository on GitHub <https://github.com/ecdavis/pants-bench/blob/751948121519248c682f2f189f5b48e2015d2bc0/.siegerc>`_. siege was run from the command line with no options specified.
The tool was run three times on each server, with the best result being taken
as representative of the servers performance in that benchmark.

Frameworks
----------

The following frameworks were tested in this benchmark:

* `asyncore <http://docs.python.org/library/asyncore.html>`_ 2.51 + `asynchat <http://docs.python.org/library/asynchat.html>`_ 2.26
* `eventlet <http://eventlet.net/>`_ 0.9.16
* `Pants  <http://pantsweb.org/>`_ |release|
* `Tornado <http://tornadoweb.org/>`_ 2.0
* `Twisted <http://twistedmatrix.com/>`_ 11.0.0

These frameworks were chosen for their prominent positions in the Python
ecosystem (with the exception of Pants, of course). We intend to run this
benchmark again against a far greater number of frameworks in the future.

Scenarios
---------

Three scenarios were enacted in this benchmark:

* **Fake HTTP**: The server continuously reads data from the client. When it
  encounters the sequence ``\r\n\r\n`` it immediately sends a
  prefabricated HTTP response with the status code 200 OK. This scenario was
  designed to test the underlying framework using siege. The frameworks
  tested were: asyncore, eventlet, Pants, Tornado and Twisted.
* **HTTP**: A "raw" HTTP server reads requests from the client and responds
  with a pre-fabricated HTTP/1.1 response with the status code 200 OK. This
  scenario was designed to test the ability of the framework to parse HTTP
  requests effectively. The frameworks tested were: Pants, Tornado and
  Twisted.
* **WSGI**: A WSGI server is run with a trivial application plugged in. This
  scenario was designed to test the WSGI capabilities of the various
  frameworks. The frameworks tested were: eventlet, Pants, Tornado and
  Twisted.


Results
=======

Fake HTTP Performance
---------------------

.. image:: /_static/charts/fake-http.png
    :align: center

+-----------+-----------------+--------------------+--------------------+
| Framework | Requests/Second | Avg. Response Time | Max. Response Time |
+===========+=================+====================+====================+
| asyncore  | 24933.07        | 0.01s              | 0.03s              |
+-----------+-----------------+--------------------+--------------------+
| eventlet  | 19531.68        | 0.01s              | 0.04s              |
+-----------+-----------------+--------------------+--------------------+
| Pants     | 20970.72        | 0.01s              | 0.04s              |
+-----------+-----------------+--------------------+--------------------+
| Tornado   | 15838.06        | 0.02s              | 0.03s              |
+-----------+-----------------+--------------------+--------------------+
| Twisted   | 17067.44        | 0.01s              | 0.05s              |
+-----------+-----------------+--------------------+--------------------+


HTTP Performance
----------------

.. image:: /_static/charts/http.png
    :align: center

+-----------+-----------------+--------------------+--------------------+
| Framework | Requests/Second | Avg. Response Time | Max. Response Time |
+===========+=================+====================+====================+
| Pants     | 9974.41         | 0.02s              | 0.06s              |
+-----------+-----------------+--------------------+--------------------+
| Tornado   | 5102.2          | 0.05s              | 0.10s              |
+-----------+-----------------+--------------------+--------------------+
| Twisted   | 3103.77         | 0.08s              | 0.19s              |
+-----------+-----------------+--------------------+--------------------+

WSGI Performance
----------------

.. image:: /_static/charts/wsgi.png
    :align: center

+-----------+-----------------+--------------------+--------------------+
| Framework | Requests/Second | Avg. Response Time | Max. Response Time |
+===========+=================+====================+====================+
| eventlet  | 3489.4          | 0.07ms             | 0.16s              |
+-----------+-----------------+--------------------+--------------------+
| Pants     | 6263.93         | 0.04ms             | 0.09s              |
+-----------+-----------------+--------------------+--------------------+
| Tornado   | 3728.03         | 0.07ms             | 0.13s              |
+-----------+-----------------+--------------------+--------------------+
| Twisted   | 1711.79         | 0.15ms             | 0.23s              |
+-----------+-----------------+--------------------+--------------------+

