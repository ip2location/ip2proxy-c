# IP2Proxy C Library

To detect proxy servers with country, region, city, ISP and proxy type information using IP2Proxy binary database.

IP2Proxy database contains a list of daily-updated IP addresses which are being used as VPN anonymizer, open proxies, web proxies and Tor exits. The database includes records for IPv4 addresses.

You can access to the commercial databases from https://www.ip2location.com/proxy-database or use the free IP2Proxy LITE database from http://lite.ip2location.com

For more details, please visit:
[http://www.ip2location.com/ip2proxy/developers/c](http://www.ip2location.com/ip2proxy/developers/c)

## Installation

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

## Testing

    cd test
    ./test-IP2Proxy

## Sample BIN Databases

* Download free IP2Proxy LITE databases at [https://lite.ip2location.com](https://lite.ip2location.com)  
* Download IP2Proxy sample databases at [https://www.ip2location.com/ip2proxy/developers](https://www.ip2location.com/ip2proxy/developers)

## Methods

Below are the methods supported in this library.

| Method Name                   | Description                                                  |
| ----------------------------- | ------------------------------------------------------------ |
| IP2Proxy_open                 | Open the IP2Proxy BIN data with **File I/O** mode for lookup. |
| IP2Proxy_open_csv             | Open the IP2Proxy CSV file for lookup. Slower performance.   |
| IP2Proxy_open_mem             | Open the IP2Proxy BIN data with **Shared Memory** or **Memory Cache** mode to speed up lookup. |
| IP2Proxy_close                | Close and clean up the file pointer.                         |
| IP2Proxy_get_package_version  | Get the package version (1 to 4 for PX1 to PX8 respectively). |
| IP2Proxy_get_module_version   | Get the module version.                                      |
| IP2Proxy_get_database_version | Get the database version.                                    |
| IP2Proxy_is_proxy             | Check wether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address</li></ul> |
| IP2Proxy_get_all              | Return the proxy information in array.                       |
| IP2Proxy_get_proxy_type       | Return the proxy type. Please visit <a href="https://www.ip2location.com/databases/px4-ip-proxytype-country-region-city-isp" target="_blank">IP2Location</a> for the list of proxy types supported |
| IP2Proxy_get_country_short    | Return the ISO3166-1 country code (2-digits) of the proxy.   |
| IP2Proxy_get_country_long     | Return the ISO3166-1 country name of the proxy.              |
| IP2Proxy_get_region           | Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported |
| IP2Proxy_get_city             | Return the city name of the proxy.                           |
| IP2Proxy_get_isp              | Return the ISP name of the proxy.                            |
| IP2Proxy_get_domain           | Return internet domain name associated with IP address range. |
| IP2Proxy_get_usage_type       | Return usage type classification of ISP or company.          |
| IP2Proxy_get_asn              | Return autonomous system number (ASN).                       |
| IP2Proxy_get_as               | Return autonomous system (AS) name.                          |
| IP2Proxy_get_last_seen        | Return proxy last seen in days.                              |
| IP2Proxy_get_threat           | Return security threat reported.                             |



## Usage

Open and read IP2Proxy binary database. There are 3 modes:

1. IP2Proxy_open("SAMPLE.BIN") - File I/O reading. Slower look, but low resource consuming.
2. IP2Proxy_open_csv("SAMPLE.CSV") - CSV parsing. Slowest, but convenient to use.
3. IP2Proxy_open_mem(IP2ProxyObj, IP2PROXY_SHARED_MEMORY) - Stores whole IP2Proxy database into system memory. Lookup is possible across all applications within the system.  Extremely resources 
   consuming. Do not use this mode if your system do not have enough 
   memory.
4. IP2Proxy_open_mem(IP2ProxyObj, IP2PROXY_CACHE_MEMORY) - Caches database into memory for faster lookup. Required high memory.



##Support

Email: support@ip2location.com.  
URL: [https://www.ip2location.com](https://www.ip2location.com)
