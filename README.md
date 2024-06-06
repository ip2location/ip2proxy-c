# IP2Proxy C Library

To detect proxy servers with country, region, city, ISP and proxy type information using IP2Proxy binary database.

IP2Proxy database contains a list of daily-updated IP addresses which are being used as VPN servers, open proxies, web proxies, Tor exit nodes, search engine robots, data center ranges, residential proxies, consumer privacy networks, and enterprise private networks. The database includes records for IPv4 addresses.

You can access to the commercial databases from https://www.ip2location.com/proxy-database or use the free IP2Proxy LITE database from http://lite.ip2location.com

For more details, please visit:
[http://www.ip2location.com/ip2proxy/developers/c](http://www.ip2location.com/ip2proxy/developers/c)



## Developer Documentation

To learn more about installation, usage, and code examples, please visit the developer documentation at [https://ip2proxy-c.readthedocs.io/en/latest/index.html.](https://ip2proxy-c.readthedocs.io/en/latest/index.html)



## Testing

    cd test
    ./test-IP2Proxy



## Sample BIN Databases

* Download free IP2Proxy LITE databases at [https://lite.ip2location.com](https://lite.ip2location.com)  
* Download IP2Proxy sample databases at [https://www.ip2location.com/ip2proxy/developers](https://www.ip2location.com/ip2proxy/developers)



## IP2Proxy CLI

Query an IP address and display the result

```
ip2proxy -d [IP2PROXY BIN DATA PATH] --ip [IP ADDRESS]
```

Query all IP addresses from an input file and display the result

```
ip2proxy -d [IP2PROXY BIN DATA PATH] -i [INPUT FILE PATH]
```

Query all IP addresses from an input file and display the result in XML format

```
ip2proxy -d [IP2PROXY BIN DATA PATH] -i [INPUT FILE PATH] --format XML
```



## Support

Email: support@ip2location.com.  
URL: [https://www.ip2location.com](https://www.ip2location.com)
