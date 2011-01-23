#!/usr/bin/env python

from distutils.core import setup

setup(
    name="pants",
    version="0.9.2",
    description="A lightweight framework for writing asynchronous network applications in Python.",
    author="Christopher Davis",
    author_email="chris@wtfrak.com",
    url="http://pants.wtfrak.com/",
    download_url="http://pants.wtfrak.com/release/pants-0.9.2.zip",
    packages=["pants"],
    classifiers=[
        "Programming Language :: Python :: 2.6",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Other Environment",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
    )