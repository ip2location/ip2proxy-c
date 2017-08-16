# IP2Proxy C Library

To detect proxy servers with country, region, city, ISP and proxy type information using IP2Proxy binary database.

IP2Proxy database contains a list of daily-updated IP addresses which are being used as VPN anonymizer, open proxies, web proxies and Tor exits. The database includes records for IPv4 addresses.

You can access to the commercial databases from https://www.ip2location.com/proxy-database or use the free IP2Proxy LITE database from http://lite.ip2location.com

For more details, please visit:
[http://www.ip2location.com/ip2proxy/developers/c](http://www.ip2location.com/ip2proxy/developers/c)

# Installation
###  Unix/Linux
    autoreconf -i -v --force
    ./configure
    make

### Windows
    Execute "vcvarsall.bat". (This file is part of Microsoft Visual C, not ip2location code) 
    nmake -f Makefile.win

### MacOS
    autoreconf -i -v --force
    export CFLAGS=-I/usr/include/malloc 
    ./configure
    make

# Testing
    cd test
    ./test-IP2Proxy

# Sample BIN Databases
* Download free IP2Proxy LITE databases at [http://lite.ip2location.com](http://lite.ip2location.com)  
* Download IP2Proxy sample databases at [http://www.ip2location.com/ip2proxy/developers](http://www.ip2location.com/ip2proxy/developers)

# Support
Email: support@ip2location.com.  
URL: [http://www.ip2location.com](http://www.ip2location.com)
