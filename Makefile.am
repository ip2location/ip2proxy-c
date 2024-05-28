bin_PROGRAMS=ip2proxy

ip2proxy_SOURCES=ip2proxy.c libIP2Proxy/IP2Proxy.c
ip2proxy_LDADD=-lrt
ip2proxy_CFLAGS=-IlibIP2Proxy -Wall

dist_man_MANS=ip2proxy.1

AM_CPPFLAGS = -Wall
SUBDIRS =	libIP2Proxy	test	$(NULL)