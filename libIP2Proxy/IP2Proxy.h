/*
 * IP2Proxy C library is distributed under LGPL version 3
 * Copyright (c) 2013-2017 IP2Proxy.com. support at ip2location dot com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not see <http://www.gnu.org/licenses/>.
 */
#ifndef HAVE_IP2PROXY_H
#define HAVE_IP2PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#if !defined(__APPLE__)
#include <stdlib.h>
#endif

#ifdef WIN32
#define int16_t short
#define int32_t int
#define int64_t long long int
#endif

#ifndef WIN32
#include <stdint.h>
#else

#ifndef uint8_t
#define uint8_t unsigned char
#endif

#ifndef uint16_t
#define uint16_t short
#endif

#ifndef int32_t
#define int32_t int
#endif

#ifndef int64_t
#define int64_t long long int
#endif

#ifndef uint32_t
#ifndef WIN32
#define uint32_t int
#else
#define uint32_t unsigned int
#endif
#endif
#endif

#include "IP2Loc_DBInterface.h"

#define API_VERSION	1.0.0

#define API_VERSION_MAJOR	1
#define API_VERSION_MINOR	0
#define API_VERSION_RELEASE	0
#define API_VERSION_NUMERIC (((API_VERSION_MAJOR * 100) + API_VERSION_MINOR) * 100 + API_VERSION_RELEASE)

#define MAX_IPV4_RANGE	4294967295U
#define IPV4	0

#define COUNTRYSHORT	0x00001
#define COUNTRYLONG		0x00002
#define REGION			0x00004
#define CITY			0x00008
#define ISP				0x00010
#define ISPROXY			0x00020
#define PROXYTYPE		0x00040

#define ALL	COUNTRYSHORT | COUNTRYLONG | REGION | CITY | ISP | ISPROXY | PROXYTYPE

#define DEFAULT			0x0001
#define NO_EMPTY_STRING	0x0002
#define NO_LEADING		0x0004
#define NO_TRAILING		0x0008

#define INVALID_IPV4_ADDRESS "INVALID IPV4 ADDRESS"
#define NOT_SUPPORTED "NOT SUPPORTED"


typedef struct
{
	FILE *filehandle;
	uint8_t is_csv;
	uint8_t databasetype;
	uint8_t databasecolumn;
	uint8_t databaseday;
	uint8_t databasemonth;
	uint8_t databaseyear;
	uint32_t databasecount;
	uint32_t databaseaddr;
	uint32_t ipversion;
	uint32_t ipv4databasecount;
	uint32_t ipv4databaseaddr;
	uint32_t ipv4indexbaseaddr;
} IP2Proxy;

typedef struct
{
	char *country_short;
	char *country_long;
	char *region;
	char *city;
	char *isp;
	char *is_proxy;
	char *proxy_type;
} IP2ProxyRecord;

/*##################
# Public Functions
##################*/
IP2Proxy *IP2Proxy_open(char *db);
IP2Proxy *IP2Proxy_open_csv(char *csv);
int IP2Proxy_open_mem(IP2Proxy *loc, enum IP2Proxy_mem_type);
uint32_t IP2Proxy_close(IP2Proxy *loc);
IP2ProxyRecord *IP2Proxy_get_country_short(IP2Proxy *loc, char *ip);
IP2ProxyRecord *IP2Proxy_get_country_long(IP2Proxy *loc, char *ip);
IP2ProxyRecord *IP2Proxy_get_region(IP2Proxy *loc, char *ip);
IP2ProxyRecord *IP2Proxy_get_city (IP2Proxy *loc, char *ip);
IP2ProxyRecord *IP2Proxy_get_isp(IP2Proxy *loc, char *ip);
IP2ProxyRecord *IP2Proxy_is_proxy(IP2Proxy *loc, char *ip);
IP2ProxyRecord *IP2Proxy_get_proxy_type(IP2Proxy *loc, char *ip);
IP2ProxyRecord *IP2Proxy_get_all(IP2Proxy *loc, char *ip);
void IP2Proxy_free_record(IP2ProxyRecord *record);
void IP2Proxy_delete_shm();
char *IP2Proxy_get_module_version(void);
char *IP2Proxy_get_package_version(IP2Proxy *loc);
char *IP2Proxy_get_database_version(IP2Proxy *loc);

#ifdef __cplusplus
}
#endif

#endif
