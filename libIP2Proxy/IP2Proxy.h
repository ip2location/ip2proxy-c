/*
 * IP2Proxy C library is distributed under MIT license
 * Copyright (c) 2013-2022 IP2Location.com. support at ip2location dot com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT license
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

#define API_VERSION			4.1.0
#define API_VERSION_MAJOR	4
#define API_VERSION_MINOR	1
#define API_VERSION_RELEASE	0
#define API_VERSION_NUMERIC (((API_VERSION_MAJOR * 100) + API_VERSION_MINOR) * 100 + API_VERSION_RELEASE)

#define MAX_IPV4_RANGE	4294967295U
#define MAX_IPV6_RANGE	"340282366920938463463374607431768211455"
#define IPV4	0
#define IPV6	1

#define COUNTRYSHORT	0x00001
#define COUNTRYLONG		0x00002
#define REGION			0x00004
#define CITY			0x00008
#define ISP				0x00010
#define ISPROXY			0x00020
#define PROXYTYPE		0x00040
#define DOMAINNAME		0x00080
#define USAGETYPE		0x00100
#define ASN				0x00200
#define AS				0x00400
#define LASTSEEN		0x00800
#define THREAT			0x01000
#define PROVIDER		0x01200

#define ALL	COUNTRYSHORT | COUNTRYLONG | REGION | CITY | ISP | ISPROXY | PROXYTYPE | DOMAINNAME | USAGETYPE | ASN | AS | LASTSEEN | THREAT

#define INVALID_IP_ADDRESS					"INVALID IP ADDRESS"
#define IPV6_ADDRESS_MISSING_IN_IPV4_BIN	"IPV6 ADDRESS MISSING IN IPV4 BIN"
#define NOT_SUPPORTED						"NOT SUPPORTED"
#define INVALID_BIN_DATABASE				"Incorrect IP2Proxy BIN file format. Please make sure that you are using the latest IP2Proxy BIN file."
#define IP2PROXY_SHM						"/IP2Proxy_Shm"
#define MAP_ADDR							4194500608

enum IP2Proxy_lookup_mode {
	IP2PROXY_FILE_IO,
	IP2PROXY_CACHE_MEMORY,
	IP2PROXY_SHARED_MEMORY
};

typedef struct {
	FILE *file;
	uint8_t is_csv;
	uint8_t database_type;
	uint8_t database_column;
	uint8_t database_day;
	uint8_t database_month;
	uint8_t database_year;
	uint8_t product_code;
	uint8_t license_code;
	uint32_t ipv4_database_count;
	uint32_t ipv4_database_address;
	uint32_t ipv4_index_base_address;
	uint32_t ipv6_database_count;
	uint32_t ipv6_database_address;
	uint32_t ipv6_index_base_address;
	uint32_t database_size;
} IP2Proxy;

typedef struct {
	char *country_short;
	char *country_long;
	char *region;
	char *city;
	char *isp;
	char *is_proxy;
	char *proxy_type;
	char *domain;
	char *usage_type;
	char *asn;
	char *as_;
	char *last_seen;
	char *threat;
	char *provider;
} IP2ProxyRecord;

/* Public functions */
unsigned long int IP2Proxy_version_number(void);
char *IP2Proxy_version_string(void);
char *IP2Proxy_get_database_version(IP2Proxy *handler);

char *IP2Proxy_get_module_version(void);
char *IP2Proxy_get_package_version(IP2Proxy *handler);

int IP2Proxy_open_mem(IP2Proxy *handler, enum IP2Proxy_lookup_mode);
int IP2Proxy_set_lookup_mode(IP2Proxy *handler, enum IP2Proxy_lookup_mode);

IP2Proxy *IP2Proxy_open(char *db);
IP2Proxy *IP2Proxy_open_csv(char *csv);

IP2ProxyRecord *IP2Proxy_get_all(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_as(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_asn(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_city (IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_country_long(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_country_short(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_domain(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_isp(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_last_seen(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_proxy_type(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_region(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_threat(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_usage_type(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_is_proxy(IP2Proxy *handler, char *ip);
IP2ProxyRecord *IP2Proxy_get_provider(IP2Proxy *handler, char *ip);

uint32_t IP2Proxy_close(IP2Proxy *handler);
void IP2Proxy_free_record(IP2ProxyRecord *record);

/* Private functions */
char *IP2Proxy_read_string(FILE *handle, uint32_t position);
float IP2Proxy_read_float(FILE *handle, uint32_t position);
float IP2Proxy_read_float_row(uint8_t* buffer, uint32_t position);
int32_t IP2Proxy_set_memory_cache(FILE *filehandle);
int32_t IP2Proxy_set_shared_memory(FILE *filehandle);
struct in6_addr IP2Proxy_read_ipv6_address(FILE *handle, uint32_t position);
struct in6_addr IP2Proxy_read128_row(uint8_t* buffer, uint32_t position);
uint32_t IP2Proxy_read32(FILE *handle, uint32_t position);
uint32_t IP2Proxy_read32_row(uint8_t* buffer, uint32_t position);
uint8_t IP2Proxy_read8(FILE *handle, uint32_t position);
int32_t IP2Proxy_close_memory(FILE *file);
void IP2Proxy_delete_shm();
void IP2Proxy_DB_del_shm();
void IP2Proxy_delete_shared_memory();
void IP2Proxy_replace(char *target, const char *needle, const char *replacement);

#ifdef __cplusplus
}
#endif
#endif