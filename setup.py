from setuptools import setup, find_packages

setup(
    name="socks5",
    version="0.2.1",
    description="SOCKSv5 bring your own io library",
    long_description="""
Socks5 bring your own io library, inspired by h11 and hyper-h2.

Source code: https://github.com/mike820324/socks5

Documentation: https://github.com/mike820324/socks5/blob/master/README.md
    """,
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
    install_requires=[
        "ipaddress==1.0.16",
        "transitions==0.4.1",
        "construct==2.8.8"
    ]
)
