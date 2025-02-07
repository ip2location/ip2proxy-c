# Quickstart

## Dependencies

This library requires IP2Proxy BIN database to function. You may download the BIN database at

-   IP2Proxy LITE BIN Data (Free): <https://lite.ip2location.com>
-   IP2Proxy Commercial BIN Data (Comprehensive):
    <https://www.ip2location.com>

:::{note}
An outdated BIN database was provided in the data folder for your testing. You are recommended to visit the above links to download the latest BIN database.
:::

## Installation

This library can be compiled and installed in different platform. Please refer to different section for the respective platform.

###  Unix/Linux
```bash
    autoreconf -i -v --force
    ./configure
    make
```

###  Debian

##### AMD64

```bash
curl -LO https://github.com/ip2location/ip2proxy-c/releases/download/4.2.0/ip2proxy-4.2.0-amd64.deb
sudo dpkg -i ip2proxy-4.2.0-amd64.deb
```



##### ARM64

```bash
curl -LO https://github.com/ip2location/ip2proxy-c/releases/download/4.2.0/ip2proxy-4.2.0-arm64.deb
sudo dpkg -i ip2proxy-4.2.0-arm64.deb
```





###  Ubuntu

```bash
sudo add-apt-repository ppa:ip2location/ip2proxy
sudo apt update
sudo apt install ip2proxy
```

### Windows
```bash
    Execute "vcvarsall.bat". (This file is part of Microsoft Visual C, not ip2location code)
    nmake -f Makefile.win
```

### MacOS
```bash
    autoreconf -i -v --force
    export CFLAGS=-I/usr/include/malloc
    ./configure
    make
```

## Sample Codes

### Query geolocation information from BIN database

You can query the geolocation information from the IP2Proxy BIN database as below:

```c
#include "IP2Proxy.h"

IP2Proxy *IP2ProxyObj = IP2Proxy_open("../data/SAMPLE.BIN");
IP2ProxyRecord *record = IP2Proxy_get_all(IP2ProxyObj, "161.11.12.13");
printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
	record->country_short,
	record->country_long,
	record->region,
	record->city,
	record->isp,
	record->is_proxy;
	record->proxy_type,
	record->domain,
	record->usage_type,
	record->asn,
	record->as_,
	record->last_seen,
	record->threat,
	record->provider,
	record->fraud_score);
IP2Proxy_free_record(record);
IP2Proxy_close(IP2ProxyObj);
```