NULL =

INCLUDES =	\
	-I$(top_srcdir)/libIP2Proxy		\
	-Wall -ansi				\
	$(NULL)

noinst_PROGRAMS = test-IP2Proxy

DEPS = $(top_builddir)/libIP2Proxy/libIP2Proxy.la
LDADDS = $(top_builddir)/libIP2Proxy/libIP2Proxy.la

test_IP2Proxy_SOURCES = test-IP2Proxy.c
test_IP2Proxy_LDFLAGS =
test_IP2Proxy_DEPENDENCIES = $(DEPS)
test_IP2Proxy_LDADD = $(LDADDS)

EXTRA_DIST = country_test_data.txt
TESTS = test-IP2Proxy
