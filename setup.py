from setuptools import setup, find_packages
from codecs import open
import os

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

with open(os.path.join(here, './requirements.txt')) as f:
    deps = [dep for dep in f.read().split("\n") if dep]

setup(
    name="socks5",
    version="0.2.0",
    description="SOCKSv5 bring your own io library",
    long_description=long_description,
    url="https://github.com/mike820324/socks5",
    author="MicroMike",
    author_email="mike820324@gmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Operating System :: POSIX",
        "Operating System :: MacOS",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Topic :: Internet",
        "Topic :: System :: Networking",
    ],
    keywords=["socks", "socks5", "protocol"],
    packages=find_packages(include=[
        "socks5", "socks5.*",
    ]),
    include_package_data=True,
    install_requires=deps,
)
