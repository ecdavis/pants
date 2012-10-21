#!/usr/bin/env python

from distutils.core import setup

setup(
    name="pants",
    version="1.0.0-beta.1",
    description="An asynchronous networking library for Python.",
    author="ecdavis",
    author_email="me@ezdwt.com",
    url="http://pantspowered.org/",
    download_url="https://github.com/ecdavis/pants/tarball/pants-1.0.0-beta.1",
    packages=["pants", "pants.contrib", "pants.http", "pants.util", "pants.web"],
    package_data={"pants.web": ["data/*.css", "data/*.png", "data/*.html"]},
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
        "bin/pants_dig.py",
        ],
    )
