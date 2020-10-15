AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I. -pipe -D _GNU_SOURCE
AM_CXXFLAGS = -Wall -Werror

lib_LTLIBRARIES = libIP2Proxy.la
include_HEADERS = IP2Proxy.h

libIP2Proxy_la_SOURCES = IP2Proxy.c

libIP2Proxy_la_LDFLAGS = -module -no-undefined -version-info 2:0:0 