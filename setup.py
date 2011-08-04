#!/usr/bin/env python

from distutils.core import setup

setup(
    name="pants",
    version="0.10.0",
    description="A lightweight framework for writing asynchronous network applications in Python.",
    author="Christopher Davis",
    author_email="chris@wtfrak.com",
    url="http://pantsweb.org/",
    download_url="https://github.com/ecdavis/Pants/zipball/pants-0.10.0",
    packages=["pants", "pants.contrib", "pants.contrib.http", "pants.util"],
    classifiers=[
        "Programming Language :: Python :: 2.6",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Other Environment",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Topic :: Internet",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Server",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
    scripts=[
        "bin/pantsd.py",
        "bin/pants_dig.py",
        ],
    )
