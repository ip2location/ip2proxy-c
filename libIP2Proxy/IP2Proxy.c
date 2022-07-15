/*
 * IP2Proxy C library is distributed under MIT license
 * Copyright (c) 2013-2022 IP2Location.com. support at ip2location dot com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT license
 */

#ifdef WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <stdint.h>
	#include <strings.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <unistd.h>
	#include <sys/mman.h>
#endif

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include "IP2Proxy.h"

#ifdef _WIN32
	#define _STR2(x) #x
	#define _STR(x) _STR2(x)
	#define PACKAGE_VERSION _STR(API_VERSION)
#else
	#include "../config.h"
#endif

typedef struct ip_container {
	uint32_t version;
	uint32_t ipv4;
	struct in6_addr ipv6;
} ip_container;

uint8_t IP2PROXY_PROXY_TYPE_POSITION[12]	= {0,   0,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2};
uint8_t IP2PROXY_COUNTRY_POSITION[12]		= {0,   2,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3};
uint8_t IP2PROXY_REGION_POSITION[12]		= {0,   0,   0,   4,   4,   4,   4,   4,   4,   4,   4,   4};
uint8_t IP2PROXY_CITY_POSITION[12]			= {0,   0,   0,   5,   5,   5,   5,   5,   5,   5,   5,   5};
uint8_t IP2PROXY_ISP_POSITION[12]			= {0,   0,   0,   0,   6,   6,   6,   6,   6,   6,   6,   6};
uint8_t IP2PROXY_DOMAIN_POSITION[12]		= {0,   0,   0,   0,   0,   7,   7,   7,   7,   7,   7,   7};
uint8_t IP2PROXY_USAGE_TYPE_POSITION[12]	= {0,   0,   0,   0,   0,   0,   8,   8,   8,   8,   8,   8};
uint8_t IP2PROXY_ASN_POSITION[12]			= {0,   0,   0,   0,   0,   0,   0,   9,   9,   9,   9,   9};
uint8_t IP2PROXY_AS_POSITION[12]			= {0,   0,   0,   0,   0,   0,   0,  10,  10,  10,  10,  10};
uint8_t IP2PROXY_LAST_SEEN_POSITION[12]		= {0,   0,   0,   0,   0,   0,   0,   0,  11,  11,  11,  11};
uint8_t IP2PROXY_THREAT_POSITION[12]		= {0,   0,   0,   0,   0,   0,   0,   0,   0,  12,  12,  12};
uint8_t IP2PROXY_PROVIDER_POSITION[12]		= {0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  13};

// Static variables
static int32_t is_in_memory = 0;
static enum IP2Proxy_lookup_mode lookup_mode = IP2PROXY_FILE_IO; /* Set default lookup mode as File I/O */
static void *memory_pointer;

// Static functions
static int IP2Proxy_initialize(IP2Proxy *handler);
static int IP2Proxy_is_ipv4(char* ip);
static int IP2Proxy_is_ipv6(char* ip);
static int32_t IP2Proxy_load_database_into_memory(FILE *file, void *memory_pointer, int64_t size);
static IP2ProxyRecord *IP2Proxy_new_record();
static IP2ProxyRecord *IP2Proxy_get_record(IP2Proxy *handler, char *ip, uint32_t mode);
static IP2ProxyRecord *IP2Proxy_get_ipv4_record(IP2Proxy *handler, uint32_t mode, ip_container parsed_ip);
static IP2ProxyRecord *IP2Proxy_get_ipv6_record(IP2Proxy *handler, uint32_t mode, ip_container parsed_ip);

#ifndef WIN32
static int32_t shm_fd;
#else
#ifdef WIN32
HANDLE shm_fd;
#endif
#endif

// Open IP2Proxy BIN database file
IP2Proxy *IP2Proxy_open(char *bin)
{
	FILE *f;
	IP2Proxy *handler;

	if ((f = fopen(bin, "rb")) == NULL) {
		printf("IP2Proxy library error in opening database %s.\n", bin);
		return NULL;
	}

	handler = (IP2Proxy *) calloc(1, sizeof(IP2Proxy));
	handler->file = f;

	IP2Proxy_initialize(handler);

	if (handler->product_code == 2) {
	} else {
		if (handler->database_year <= 20 && handler->product_code == 0) {
		} else {
			printf(INVALID_BIN_DATABASE);
			return NULL;
		}
	}

	return handler;
}

IP2Proxy *IP2Proxy_open_csv(char *csv)
{
	IP2Proxy *handler;
	FILE *fp;
	char line[2048];
	char *delimiter = ";";
	char *token;

	int column = 0;

	if ((fp = fopen(csv, "r")) == NULL) {
		printf("Error when opening CSV file.");
		return NULL;
	}

	handler = (IP2Proxy *) calloc(1, sizeof(IP2Proxy));
	handler->file = fp;
	handler->is_csv = 1;

	if (fgets(line, 512, fp) != NULL) {
		rewind(fp);
		IP2Proxy_replace(line, "\",\"", ";");
		IP2Proxy_replace(line, "\"", "");

		token = strtok(line, delimiter);

		while (token != NULL) {
			column++;
			token = strtok(NULL, delimiter);
		}
	}

	switch (column) {
		case 4:
			handler->database_type = 1;
			break;

		case 5:
			handler->database_type = 2;
			break;

		case 7:
			handler->database_type = 3;
			break;

		case 8:
			handler->database_type = 4;
			break;
	}

	return handler;
}

// Set lookup mode (Will deprecate in next major version update)
int32_t IP2Proxy_open_mem(IP2Proxy *handler, enum IP2Proxy_lookup_mode mode)
{
	return IP2Proxy_set_lookup_mode(handler, mode);
}


// Set lookup mode
int32_t IP2Proxy_set_lookup_mode(IP2Proxy *handler, enum IP2Proxy_lookup_mode mode)
{
	// BIN database is not loaded
	if (handler == NULL) {
		return -1;
	}

	// Existing database already loaded into memory
	if (is_in_memory != 0) {
		return -1;
	}

	// Mark database loaded into memory
	is_in_memory = 1;

	if (mode == IP2PROXY_FILE_IO) {
		return 0;
	} else if (mode == IP2PROXY_CACHE_MEMORY) {
		return IP2Proxy_set_memory_cache(handler->file);
	} else if (mode == IP2PROXY_SHARED_MEMORY) {
		return IP2Proxy_set_shared_memory(handler->file);
	} else {
		return -1;
	}
}

// Close IP2Proxy handler
uint32_t IP2Proxy_close(IP2Proxy *handler)
{
	is_in_memory = 0;

	if (handler != NULL) {
		IP2Proxy_close_memory(handler->file);
		free(handler);
	}

	return 0;
}

// Clear memory object (Will deprecate in next major version update)
void IP2Proxy_delete_shm()
{
	IP2Proxy_delete_shared_memory();
}

void IP2Proxy_DB_del_shm()
{
	IP2Proxy_delete_shared_memory();
}

// Initialize database structures
static int IP2Proxy_initialize(IP2Proxy *handler)
{
	uint8_t buffer[64];
	uint32_t mem_offset = 1;
	
	if (lookup_mode == IP2PROXY_FILE_IO) {
		fread(buffer, sizeof(buffer), 1, handler->file);
	}

	handler->database_type = IP2Proxy_read8_row((uint8_t*)buffer, 0, mem_offset);
	handler->database_column = IP2Proxy_read8_row((uint8_t*)buffer, 1, mem_offset);
	handler->database_year = IP2Proxy_read8_row((uint8_t*)buffer, 2, mem_offset);
	handler->database_month = IP2Proxy_read8_row((uint8_t*)buffer, 3, mem_offset);
	handler->database_day = IP2Proxy_read8_row((uint8_t*)buffer, 4, mem_offset);
	
	handler->ipv4_database_count = IP2Proxy_read32_row((uint8_t*)buffer, 5, mem_offset);
	handler->ipv4_database_address = IP2Proxy_read32_row((uint8_t*)buffer, 9, mem_offset);
	handler->ipv6_database_count = IP2Proxy_read32_row((uint8_t*)buffer, 13, mem_offset);
	handler->ipv6_database_address = IP2Proxy_read32_row((uint8_t*)buffer, 17, mem_offset);
	handler->ipv4_index_base_address = IP2Proxy_read32_row((uint8_t*)buffer, 21, mem_offset);
	handler->ipv6_index_base_address = IP2Proxy_read32_row((uint8_t*)buffer, 25, mem_offset);
	handler->product_code = IP2Proxy_read8_row((uint8_t*)buffer, 29, mem_offset);
	handler->license_code = IP2Proxy_read8_row((uint8_t*)buffer, 30, mem_offset);
	handler->database_size = IP2Proxy_read32_row((uint8_t*)buffer, 31, mem_offset);

	return 0;
}

// Compare IPv6 address
int IP2Proxy_ipv6_compare(struct in6_addr *addr1, struct in6_addr *addr2)
{
	int i, ret = 0;
	for (i = 0; i < 16; i++) {
		if (addr1->s6_addr[i] > addr2->s6_addr[i]) {
			ret = 1;
			break;
		} else if (addr1->s6_addr[i] < addr2->s6_addr[i]) {
			ret = -1;
			break;
		}
	}

	return ret;
}

// Parse IP address into binary address for lookup purpose
static ip_container IP2Proxy_parse_address(const char *ip)
{
	ip_container parsed;

	if (IP2Proxy_is_ipv4((char *) ip)) {
		// Parse IPv4 address
		parsed.version = 4;
		inet_pton(AF_INET, ip, &parsed.ipv4);
		parsed.ipv4 = htonl(parsed.ipv4);
	} else if (IP2Proxy_is_ipv6((char *) ip)) {
		// Parse IPv6 address
		inet_pton(AF_INET6, ip, &parsed.ipv6);

		// IPv4 Address in IPv6
		if (parsed.ipv6.s6_addr[0] == 0 && parsed.ipv6.s6_addr[1] == 0 && parsed.ipv6.s6_addr[2] == 0 && parsed.ipv6.s6_addr[3] == 0 && parsed.ipv6.s6_addr[4] == 0 && parsed.ipv6.s6_addr[5] == 0 && parsed.ipv6.s6_addr[6] == 0 && parsed.ipv6.s6_addr[7] == 0 && parsed.ipv6.s6_addr[8] == 0 && parsed.ipv6.s6_addr[9] == 0 && parsed.ipv6.s6_addr[10] == 255 && parsed.ipv6.s6_addr[11] == 255) {
			parsed.version = 4;
			parsed.ipv4 = (parsed.ipv6.s6_addr[12] << 24) + (parsed.ipv6.s6_addr[13] << 16) + (parsed.ipv6.s6_addr[14] << 8) + parsed.ipv6.s6_addr[15];
		}

		// 6to4 Address - 2002::/16
		else if (parsed.ipv6.s6_addr[0] == 32 && parsed.ipv6.s6_addr[1] == 2) {
			parsed.version = 4;
			parsed.ipv4 = (parsed.ipv6.s6_addr[2] << 24) + (parsed.ipv6.s6_addr[3] << 16) + (parsed.ipv6.s6_addr[4] << 8) + parsed.ipv6.s6_addr[5];
		}

		// Teredo Address - 2001:0::/32
		else if (parsed.ipv6.s6_addr[0] == 32 && parsed.ipv6.s6_addr[1] == 1 && parsed.ipv6.s6_addr[2] == 0 && parsed.ipv6.s6_addr[3] == 0) {
			parsed.version = 4;
			parsed.ipv4 = ~((parsed.ipv6.s6_addr[12] << 24) + (parsed.ipv6.s6_addr[13] << 16) + (parsed.ipv6.s6_addr[14] << 8) + parsed.ipv6.s6_addr[15]);
		}

		// Common IPv6 Address
		else {
			parsed.version = 6;
		}
	} else {
		// Invalid IP address
		parsed.version = -1;
	}

	return parsed;
}

// Get country code
IP2ProxyRecord *IP2Proxy_get_country_short(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, COUNTRYSHORT);
}

// Get country name
IP2ProxyRecord *IP2Proxy_get_country_long(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, COUNTRYLONG);
}

// Get the name of state/region
IP2ProxyRecord *IP2Proxy_get_region(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, REGION);
}

// Get city name
IP2ProxyRecord *IP2Proxy_get_city (IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, CITY);
}

// Get ISP name
IP2ProxyRecord *IP2Proxy_get_isp(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, ISP);
}

// Is Proxy
IP2ProxyRecord *IP2Proxy_is_proxy(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, ISPROXY);
}

// Get Proxy type
IP2ProxyRecord *IP2Proxy_get_proxy_type(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, PROXYTYPE);
}

// Get Domain
IP2ProxyRecord *IP2Proxy_get_domain(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, DOMAINNAME);
}

// Get Usage type
IP2ProxyRecord *IP2Proxy_get_usage_type(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, USAGETYPE);
}

// Get ASN
IP2ProxyRecord *IP2Proxy_get_asn(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, ASN);
}

// Get AS
IP2ProxyRecord *IP2Proxy_get_as(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, AS);
}

// Get Last seen
IP2ProxyRecord *IP2Proxy_get_last_seen(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, LASTSEEN);
}

// Get Threat
IP2ProxyRecord *IP2Proxy_get_threat(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, THREAT);
}

// Get Provider
IP2ProxyRecord *IP2Proxy_get_provider(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, PROVIDER);
}

// Get all records of an IP address
IP2ProxyRecord *IP2Proxy_get_all(IP2Proxy *handler, char *ip)
{
	return IP2Proxy_get_record(handler, ip, ALL);
}

// fill the record fields with error message
static IP2ProxyRecord *IP2Proxy_bad_record(const char *message)
{
	IP2ProxyRecord *record = IP2Proxy_new_record();
	record->country_short = strdup(message);
	record->country_long = strdup(message);
	record->region = strdup(message);
	record->city = strdup(message);
	record->isp = strdup(message);
	record->is_proxy = "-1";
	record->proxy_type = strdup(message);
	record->domain = strdup(message);
	record->usage_type = strdup(message);
	record->asn = strdup(message);
	record->as_ = strdup(message);
	record->last_seen = strdup(message);
	record->threat = strdup(message);
	record->provider = strdup(message);

	return record;
}

// read the record data
static IP2ProxyRecord *IP2Proxy_read_record(IP2Proxy *handler, uint8_t* buffer, uint32_t mode, uint32_t mem_offset)
{
	uint8_t dbtype = handler->database_type;
	FILE *handle = handler->file;
	IP2ProxyRecord *record = IP2Proxy_new_record();
	record->is_proxy = "-1";

	if ((mode & ISPROXY) && (IP2PROXY_COUNTRY_POSITION[dbtype] != 0)) {
		if (!record->country_short) {
			record->country_short = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_COUNTRY_POSITION[dbtype] - 2), mem_offset));
		}

		if (strcmp(record->country_short, "-") == 0) {
			record->is_proxy = "0";
		} else {
			if (!record->proxy_type) {
				record->proxy_type = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_COUNTRY_POSITION[dbtype] - 2), mem_offset));
			}

			if (strcmp(record->proxy_type, "DCH") == 0 || strcmp(record->proxy_type, "SES") == 0) {
				record->is_proxy = "2";
			} else {
				record->is_proxy = "1";
			}

			if (IP2PROXY_PROXY_TYPE_POSITION[dbtype] == 0) {
				record->proxy_type = strdup(NOT_SUPPORTED);
			}
		}
	} else {
		record->is_proxy = "-1";
	}

	if ((mode & COUNTRYSHORT) && (IP2PROXY_COUNTRY_POSITION[dbtype] != 0)) {
		if (!record->country_short) {
			record->country_short = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_COUNTRY_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->country_short) {
			record->country_short = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & COUNTRYLONG) && (IP2PROXY_COUNTRY_POSITION[dbtype] != 0)) {
		if (!record->country_long) {
			record->country_long = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_COUNTRY_POSITION[dbtype] - 2), mem_offset)+3);
		}
	} else {
		if (!record->country_long) {
			record->country_long = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & REGION) && (IP2PROXY_REGION_POSITION[dbtype] != 0)) {
		if (!record->region) {
			record->region = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_REGION_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->region)
			record->region = strdup(NOT_SUPPORTED);
	}

	if ((mode & CITY) && (IP2PROXY_CITY_POSITION[dbtype] != 0)) {
		if (!record->city) {
			record->city = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_CITY_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->city) {
			record->city = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & ISP) && (IP2PROXY_ISP_POSITION[dbtype] != 0)) {
		if (!record->isp) {
			record->isp = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_ISP_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->isp) {
			record->isp = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & PROXYTYPE) && (IP2PROXY_PROXY_TYPE_POSITION[dbtype] != 0)) {
		if (!record->proxy_type)
			record->proxy_type = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_PROXY_TYPE_POSITION[dbtype] - 2), mem_offset));
	} else {
		if (!record->proxy_type) {
			record->proxy_type = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & DOMAINNAME) && (IP2PROXY_DOMAIN_POSITION[dbtype] != 0)) {
		if (!record->domain) {
			record->domain = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_DOMAIN_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->domain) {
			record->domain = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & USAGETYPE) && (IP2PROXY_USAGE_TYPE_POSITION[dbtype] != 0)) {
		if (!record->usage_type) {
			record->usage_type = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_USAGE_TYPE_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->usage_type) {
			record->usage_type = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & ASN) && (IP2PROXY_ASN_POSITION[dbtype] != 0)) {
		if (!record->asn) {
			record->asn = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_ASN_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->asn) {
			record->asn = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & AS) && (IP2PROXY_AS_POSITION[dbtype] != 0)) {
		if (!record->as_) {
			record->as_ = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_AS_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->as_) {
			record->as_ = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & LASTSEEN) && (IP2PROXY_LAST_SEEN_POSITION[dbtype] != 0)) {
		if (!record->last_seen) {
			record->last_seen = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_LAST_SEEN_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->last_seen) {
			record->last_seen = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & THREAT) && (IP2PROXY_THREAT_POSITION[dbtype] != 0)) {
		if (!record->threat) {
			record->threat = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_THREAT_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->threat) {
			record->threat = strdup(NOT_SUPPORTED);
		}
	}

	if ((mode & PROVIDER) && (IP2PROXY_PROVIDER_POSITION[dbtype] != 0)) {
		if (!record->provider) {
			record->provider = IP2Proxy_read_string(handle, IP2Proxy_read32_row(buffer, 4 * (IP2PROXY_PROVIDER_POSITION[dbtype] - 2), mem_offset));
		}
	} else {
		if (!record->provider) {
			record->provider = strdup(NOT_SUPPORTED);
		}
	}

	return record;
}

// Get the location data
static IP2ProxyRecord *IP2Proxy_get_record(IP2Proxy *handler, char *ip, uint32_t mode)
{
	ip_container parsed_ip = IP2Proxy_parse_address(ip);

	if (parsed_ip.version == 4) {
		return IP2Proxy_get_ipv4_record(handler, mode, parsed_ip);
	}
	if (parsed_ip.version == 6) {
		if (handler->ipv6_database_count == 0) {
			return IP2Proxy_bad_record(IPV6_ADDRESS_MISSING_IN_IPV4_BIN);
		}

		return IP2Proxy_get_ipv6_record(handler, mode, parsed_ip);
	} else {
		return IP2Proxy_bad_record(INVALID_IP_ADDRESS);
	}
}

// Get IPv4 records from database
static IP2ProxyRecord *IP2Proxy_get_ipv4_record(IP2Proxy *handler, uint32_t mode, ip_container parsed_ip)
{
	FILE *handle = handler->file;
	uint32_t ip_number;
	uint32_t ip_from;
	uint32_t ip_to;

	ip_number = parsed_ip.ipv4;

	if (ip_number == (uint32_t) MAX_IPV4_RANGE) {
		ip_number = ip_number - 1;
	}

	if (handler->is_csv == 1) {
		char line[2048];
		char *delimiter = ";";
		char *token;
		int is_found = 0;

		IP2ProxyRecord *record = IP2Proxy_new_record();
		record->is_proxy = "-1";
		record->proxy_type = NOT_SUPPORTED;
		record->region = NOT_SUPPORTED;
		record->city = NOT_SUPPORTED;
		record->isp = NOT_SUPPORTED;
		record->domain = NOT_SUPPORTED;
		record->usage_type = NOT_SUPPORTED;
		record->asn = NOT_SUPPORTED;
		record->as_ = NOT_SUPPORTED;
		record->last_seen = NOT_SUPPORTED;
		record->threat = NOT_SUPPORTED;
		record->provider = NOT_SUPPORTED;

		while (fgets(line, 2048, handle) != NULL) {
			IP2Proxy_replace(line, "\n", "");
			IP2Proxy_replace(line, "\",\"", ";");
			IP2Proxy_replace(line, "\"", "");

			token = strtok(line, delimiter);

			ip_from = atoi(token);

			token = strtok(NULL, delimiter);

			ip_to = atoi(token);

			if (ip_number >= ip_from && ip_number <= ip_to) {
				is_found = 1;
				break;
			}
		}

		if (is_found == 0) {
			record->country_short = "-";
			record->country_long = "-";
			record->region = "-";
			record->city = "-";
			record->isp = "-";
			record->is_proxy = "0";
			record->proxy_type = "-";
			record->domain = "-";
			record->usage_type = "-";
			record->asn = "-";
			record->as_ = "-";
			record->last_seen = "-";
			record->threat = "-";
			record->provider = "-";

			return record;
		}

		switch (handler->database_type) {
			case 1:
				token = strtok(NULL, delimiter);
				record->country_short = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_long = strdup(token);

				if (strcmp(record->country_short, "-") == 0) {
					record->is_proxy = "0";
				} else {
					record->is_proxy = "1";
				}

				return record;

			case 2:
				token = strtok(NULL, delimiter);
				record->proxy_type = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_short = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_long = strdup(token);

				if (strcmp(record->country_short, "-") == 0) {
					record->is_proxy = "0";
				} else if (strcmp(record->proxy_type, "DCH") == 0 || strcmp(record->proxy_type, "SES") == 0) {
					record->is_proxy = "0";
				} else {
					record->is_proxy = "1";
				}

				return record;

			case 3:
				token = strtok(NULL, delimiter);
				record->proxy_type = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_short = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_long = strdup(token);

				token = strtok(NULL, delimiter);
				record->region = strdup(token);

				token = strtok(NULL, delimiter);
				record->city = strdup(token);


				if (strcmp(record->country_short, "-") == 0) {
					record->is_proxy = "0";
				} else if (strcmp(record->proxy_type, "DCH") == 0 || strcmp(record->proxy_type, "SES") == 0) {
					record->is_proxy = "0";
				} else {
					record->is_proxy = "1";
				}

				return record;

			case 4:
				token = strtok(NULL, delimiter);
				record->proxy_type = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_short = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_long = strdup(token);

				token = strtok(NULL, delimiter);
				record->region = strdup(token);

				token = strtok(NULL, delimiter);
				record->city = strdup(token);

				token = strtok(NULL, delimiter);
				record->isp = strdup(token);

				if (strcmp(record->country_short, "-") == 0) {
					record->is_proxy = "0";
				} else if (strcmp(record->proxy_type, "DCH") == 0 || strcmp(record->proxy_type, "SES") == 0) {
					record->is_proxy = "0";
				} else {
					record->is_proxy = "1";
				}

				return record;
		} 

		return NULL;
	}

	uint32_t base_address = handler->ipv4_database_address;
	uint32_t database_column = handler->database_column;
	uint32_t ipv4_index_base_address = handler->ipv4_index_base_address;

	uint32_t low = 0;
	uint32_t high = handler->ipv4_database_count;
	uint32_t mid = 0;

	uint32_t column_offset = database_column * 4;
	uint32_t row_offset = 0;
	uint8_t full_row_buffer[200];
	uint8_t row_buffer[200];
	uint32_t full_row_size;
	uint32_t row_size;
	uint32_t mem_offset;

	if (ipv4_index_base_address > 0) {
		uint32_t number = (uint32_t) ip_number >> 16;
		uint32_t indexpos = ipv4_index_base_address + (number << 3);
		
		uint8_t indexbuffer[8];
		if (lookup_mode == IP2PROXY_FILE_IO) {
			fseek(handle, indexpos - 1, 0);
			fread(indexbuffer, sizeof(indexbuffer), 1, handle);
		}
		mem_offset = indexpos;
		low = IP2Proxy_read32_row((uint8_t*)indexbuffer, 0, mem_offset);
		high = IP2Proxy_read32_row((uint8_t*)indexbuffer, 4, mem_offset);
	}

	full_row_size = column_offset + 4;
	row_size = column_offset - 4;

	while (low <= high) {
		mid = (uint32_t)((low + high) >> 1);
		row_offset = base_address + (mid * column_offset);
		
		if (lookup_mode == IP2PROXY_FILE_IO) {
			fseek(handle, row_offset - 1, 0);
			fread(&full_row_buffer, full_row_size, 1, handle);
		}
		mem_offset = row_offset;
		
		ip_from = IP2Proxy_read32_row((uint8_t*)full_row_buffer, 0, mem_offset);
		ip_to = IP2Proxy_read32_row((uint8_t*)full_row_buffer, column_offset, mem_offset);

		if ((ip_number >= ip_from) && (ip_number < ip_to)) {
			if (lookup_mode == IP2PROXY_FILE_IO) {
				memcpy(&row_buffer, ((uint8_t*)full_row_buffer) + 4, row_size); // extract actual row data
			}
			return IP2Proxy_read_record(handler, (uint8_t *)row_buffer, mode, mem_offset + 4);
		} else {
			if (ip_number < ip_from) {
				high = mid - 1;
			} else {
				low = mid + 1;
			}
		}
	}
	return NULL;
}

// Get IPv6 records from database
static IP2ProxyRecord * IP2Proxy_get_ipv6_record(IP2Proxy *handler, uint32_t mode, ip_container parsed_ip)
{
	FILE *handle = handler->file;
	uint32_t base_address = handler->ipv6_database_address;
	uint32_t database_column = handler->database_column;
	uint32_t ipv6_index_base_address = handler->ipv6_index_base_address;

	uint32_t low = 0;
	uint32_t high = handler->ipv6_database_count;
	uint32_t mid = 0;

	struct in6_addr ip_from;
	struct in6_addr ip_to;
	struct in6_addr ip_number;

	uint32_t column_offset = database_column * 4 + 12;
	uint32_t row_offset = 0;
	uint8_t full_row_buffer[200];
	uint8_t row_buffer[200];
	uint32_t full_row_size;
	uint32_t row_size;
	uint32_t mem_offset;

	ip_number = parsed_ip.ipv6;

	if (!high) {
		return NULL;
	}

	if (ipv6_index_base_address > 0) {
		uint32_t number = (ip_number.s6_addr[0] * 256) + ip_number.s6_addr[1];
		uint32_t indexpos = ipv6_index_base_address + (number << 3);
		
		uint8_t indexbuffer[8];
		if (lookup_mode == IP2PROXY_FILE_IO) {
			fseek(handle, indexpos - 1, 0);
			fread(indexbuffer, sizeof(indexbuffer), 1, handle);
		}
		mem_offset = indexpos;
		low = IP2Proxy_read32_row((uint8_t*)indexbuffer, 0, mem_offset);
		high = IP2Proxy_read32_row((uint8_t*)indexbuffer, 4, mem_offset);
	}

	full_row_size = column_offset + 16;
	row_size = column_offset - 16;

	while (low <= high) {
		mid = (uint32_t)((low + high) >> 1);
		row_offset = base_address + (mid * column_offset);
		
		if (lookup_mode == IP2PROXY_FILE_IO) {
			fseek(handle, row_offset - 1, 0);
			fread(&full_row_buffer, full_row_size, 1, handle);
		}
		mem_offset = row_offset;
		
		ip_from = IP2Proxy_read128_row((uint8_t *)full_row_buffer, 0, mem_offset);
		ip_to = IP2Proxy_read128_row((uint8_t *)full_row_buffer, column_offset, mem_offset);

		if ((IP2Proxy_ipv6_compare(&ip_number, &ip_from) >= 0) && (IP2Proxy_ipv6_compare(&ip_number, &ip_to) < 0)) {
			if (lookup_mode == IP2PROXY_FILE_IO) {
				memcpy(&row_buffer, ((uint8_t*)full_row_buffer) + 16, row_size); // extract actual row data
			}
			return IP2Proxy_read_record(handler, (uint8_t *)row_buffer, mode, mem_offset + 16);
		} else {
			if (IP2Proxy_ipv6_compare(&ip_number, &ip_from) < 0) {
				high = mid - 1;
			} else {
				low = mid + 1;
			}
		}
	}
	return NULL;
}

// Initialize the record object
static IP2ProxyRecord *IP2Proxy_new_record()
{
	IP2ProxyRecord *record = (IP2ProxyRecord *) calloc(1, sizeof(IP2ProxyRecord));
	return record;
}

// Free the record object
void IP2Proxy_free_record(IP2ProxyRecord *record)
{

	if (record == NULL) {
		return;
	}

	if (record->country_short != NULL) {
		free(record->country_short);
	}
	
	if (record->country_long != NULL) {
		free(record->country_long);
	}
	
	if (record->region != NULL) {
		free(record->region);
	}
	
	if (record->city != NULL) {
		free(record->city);
	}
	
	if (record->isp != NULL) {
		free(record->isp);
	}

	if (record->proxy_type != NULL) {
		free(record->proxy_type);
	}

	if (record->domain != NULL) {
		free(record->domain);
	}

	if (record->usage_type != NULL) {
		free(record->usage_type);
	}

	if (record->asn != NULL) {
		free(record->asn);
	}

	if (record->as_ != NULL) {
		free(record->as_);
	}

	if (record->last_seen != NULL) {
		free(record->last_seen);
	}

	if (record->threat != NULL) {
		free(record->threat);
	}

	if (record->threat != NULL) {
		free(record->provider);
	}

	free(record);
}

// Set to use memory caching
int32_t IP2Proxy_set_memory_cache(FILE *file)
{
	struct stat buffer;
	lookup_mode = IP2PROXY_CACHE_MEMORY;

	if (fstat(fileno(file), &buffer) == -1) {
		lookup_mode = IP2PROXY_FILE_IO;
		return -1;
	}

	if ((memory_pointer = malloc(buffer.st_size + 1)) == NULL) {
		lookup_mode = IP2PROXY_FILE_IO;
		return -1;
	}

	if (IP2Proxy_load_database_into_memory(file, memory_pointer, buffer.st_size) == -1) {
		lookup_mode = IP2PROXY_FILE_IO;
		free(memory_pointer);
		return -1;
	}

	return 0;
}

// Set to use shared memory
#ifndef WIN32
int32_t IP2Proxy_set_shared_memory(FILE *file)
{
	struct stat buffer;
	int32_t is_dababase_loaded = 1;
	void *addr = (void*)MAP_ADDR;

	lookup_mode = IP2PROXY_SHARED_MEMORY;

	// New shared memory object is created
	if ((shm_fd = shm_open(IP2PROXY_SHM, O_RDWR | O_CREAT | O_EXCL, 0777)) != -1) {
		is_dababase_loaded = 0;
	}

	// Failed to create new shared memory object
	else if ((shm_fd = shm_open(IP2PROXY_SHM, O_RDWR , 0777)) == -1) {
		lookup_mode = IP2PROXY_FILE_IO;
		return -1;
	}

	if (fstat(fileno(file), &buffer) == -1) {
		close(shm_fd);

		if (is_dababase_loaded == 0) {
			shm_unlink(IP2PROXY_SHM);
		}
		
		lookup_mode = IP2PROXY_FILE_IO;
		
		return -1;
	}

	if (is_dababase_loaded == 0 && ftruncate(shm_fd, buffer.st_size + 1) == -1) {
		close(shm_fd);
		shm_unlink(IP2PROXY_SHM);
		lookup_mode = IP2PROXY_FILE_IO;
		return -1;
	}

	memory_pointer = mmap(addr, buffer.st_size + 1, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

	if (memory_pointer == (void *) -1) {
		close(shm_fd);

		if (is_dababase_loaded == 0) {
			shm_unlink(IP2PROXY_SHM);
		}
		
		lookup_mode = IP2PROXY_FILE_IO;

		return -1;
	}
	
	if (is_dababase_loaded == 0) {
		if (IP2Proxy_load_database_into_memory(file, memory_pointer, buffer.st_size) == -1) {
			munmap(memory_pointer, buffer.st_size);
			close(shm_fd);
			shm_unlink(IP2PROXY_SHM);
			lookup_mode = IP2PROXY_FILE_IO;
			return -1;
		}
	}

	return 0;
}
#else
#ifdef WIN32
int32_t IP2Proxy_set_shared_memory(FILE *file)
{
	struct stat buffer;
	int32_t is_dababase_loaded = 1;

	lookup_mode = IP2PROXY_SHARED_MEMORY;

	if (fstat(fileno(file), &buffer) == -1) {
		lookup_mode = IP2PROXY_FILE_IO;
		return -1;
	}

	shm_fd = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, buffer.st_size + 1, TEXT(IP2PROXY_SHM));

	if (shm_fd == NULL) {
		lookup_mode = IP2PROXY_FILE_IO;
		return -1;
	}

	is_dababase_loaded = (GetLastError() == ERROR_ALREADY_EXISTS);
	memory_pointer = MapViewOfFile(shm_fd, FILE_MAP_WRITE, 0, 0, 0);

	if (memory_pointer == NULL) {
		UnmapViewOfFile(memory_pointer);
		lookup_mode = IP2PROXY_FILE_IO;
		return -1;
	}

	if (is_dababase_loaded == 0) {
		if (IP2Proxy_load_database_into_memory(file, memory_pointer, buffer.st_size) == -1) {
			UnmapViewOfFile(memory_pointer);
			CloseHandle(shm_fd);
			lookup_mode = IP2PROXY_FILE_IO;
			return -1;
		}
	}

	return 0;
}
#endif
#endif

// Load BIN file into memory
int32_t IP2Proxy_load_database_into_memory(FILE *file, void *memory, int64_t size)
{
	fseek(file, 0, SEEK_SET);
	
	if (fread(memory, size, 1, file) != 1) {
		return -1;
	}

	return 0;
}

// Close the memory
int32_t IP2Proxy_close_memory(FILE *file)
{
	struct stat buffer;
	
	if (lookup_mode == IP2PROXY_CACHE_MEMORY) {
		if (memory_pointer != NULL) {
			free(memory_pointer);
		}
	} else if (lookup_mode == IP2PROXY_SHARED_MEMORY) {
		if (memory_pointer != NULL) {
#ifndef	WIN32
			if (fstat(fileno(file), &buffer) == 0) {
				munmap(memory_pointer, buffer.st_size);
			}

			close(shm_fd);
#else
#ifdef WIN32
			UnmapViewOfFile(memory_pointer);
			CloseHandle(shm_fd);
#endif
#endif
		}
	}
	
	if (file != NULL) {
		fclose(file);
	}
	
	lookup_mode = IP2PROXY_FILE_IO;
	return 0;
}

#ifndef	WIN32
// Remove shared memory object
void IP2Proxy_delete_shared_memory()
{
	shm_unlink(IP2PROXY_SHM);
}
#else
#ifdef WIN32
void IP2Proxy_delete_shared_memory()
{
}
#endif
#endif

// Check if address is IPv4
static int IP2Proxy_is_ipv4(char *ip)
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, ip, &sa.sin_addr);
}

// Check if address is IPv6
static int IP2Proxy_is_ipv6(char *ip)
{
	struct in6_addr result;
	return inet_pton(AF_INET6, ip, &result);
}

// Get API version numeric
unsigned long int IP2Proxy_version_number(void)
{
	return (API_VERSION_NUMERIC);
}

// Get API version as string
char *IP2Proxy_version_string(void)
{
	static char version[64];
	sprintf(version, "%d.%d.%d", API_VERSION_MAJOR, API_VERSION_MINOR, API_VERSION_RELEASE);
	return (version);
}

// Get database version
char *IP2Proxy_get_database_version(IP2Proxy *handler)
{
	static char version[8];

	snprintf(version, sizeof(version), "%02d%02d%02d", handler->database_year, handler->database_month, handler->database_day);

	return version;
}

char *IP2Proxy_get_package_version(IP2Proxy *handler)
{
	static char version[3];

	snprintf(version, sizeof(version), "%d", handler->database_type);

	return version;
}

void IP2Proxy_replace(char *target, const char *needle, const char *replacement)
{
	char buffer[1024] = { 0 };
	char *insert_point = &buffer[0];
	const char *tmp = target;
	size_t needle_length = strlen(needle);
	size_t string_length = strlen(replacement);

	while (1) {
		const char *p = strstr(tmp, needle);

		// Walked past last occurrence of needle; copy remaining part
		if (p == NULL) {
			strcpy(insert_point, tmp);
			break;
		}

		// Copy part before needle
		memcpy(insert_point, tmp, p - tmp);
		insert_point += p - tmp;

		// Copy replacement string
		memcpy(insert_point, replacement, string_length);
		insert_point += string_length;

		// Adjust pointers, move on
		tmp = p + needle_length;
	}

	// Write altered string back to target
	strcpy(target, buffer);
}

struct in6_addr IP2Proxy_read128_row(uint8_t* buffer, uint32_t position, uint32_t mem_offset)
{
	int i, j;
	struct in6_addr addr6;
	for (i = 0, j = 15; i < 16; i++, j--)
	{
		addr6.s6_addr[i] = IP2Proxy_read8_row(buffer, position + j, mem_offset);
	}
	return addr6;
}

struct in6_addr IP2Proxy_read_ipv6_address(FILE *handle, uint32_t position)
{
	int i, j;
	struct in6_addr addr6;
	
	for (i = 0, j = 15; i < 16; i++, j--) {
		addr6.s6_addr[i] = IP2Proxy_read8(handle, position + j);
	}

	return addr6;
}

uint32_t IP2Proxy_read32(FILE *handle, uint32_t position)
{
	uint8_t byte1 = 0;
	uint8_t byte2 = 0;
	uint8_t byte3 = 0;
	uint8_t byte4 = 0;
	uint8_t *cache_shm = memory_pointer;
	size_t temp;
	
	// Read from file
	if (lookup_mode == IP2PROXY_FILE_IO && handle != NULL) {
		fseek(handle, position - 1, SEEK_SET);
		temp = fread(&byte1, 1, 1, handle);

		if (temp == 0) {
			return 0;
		}

		temp = fread(&byte2, 1, 1, handle);

		if (temp == 0) {
			return 0;
		}

		temp = fread(&byte3, 1, 1, handle);
		
		if (temp == 0) {
			return 0;
		}
		
		temp = fread(&byte4, 1, 1, handle);
		
		if (temp == 0) {
			return 0;
		}
	} else {
		byte1 = cache_shm[position - 1];
		byte2 = cache_shm[position];
		byte3 = cache_shm[position + 1];
		byte4 = cache_shm[position + 2];
	}

	return ((byte4 << 24) | (byte3 << 16) | (byte2 << 8) | (byte1));
}

uint32_t IP2Proxy_read32_row(uint8_t* buffer, uint32_t position, uint32_t mem_offset)
{
	uint32_t val = 0;
	uint8_t byte1 = 0;
	uint8_t byte2 = 0;
	uint8_t byte3 = 0;
	uint8_t byte4 = 0;
	uint8_t *cache_shm = memory_pointer;
	
	if (lookup_mode == IP2PROXY_FILE_IO) {
		memcpy(&val, buffer + position, 4);
		return val;
	} else {
		byte1 = cache_shm[mem_offset + position - 1];
		byte2 = cache_shm[mem_offset + position];
		byte3 = cache_shm[mem_offset + position + 1];
		byte4 = cache_shm[mem_offset + position + 2];
		return ((byte4 << 24) | (byte3 << 16) | (byte2 << 8) | (byte1));
	}
}

uint8_t IP2Proxy_read8(FILE *handle, uint32_t position)
{
	uint8_t ret = 0;
	uint8_t *cache_shm = memory_pointer;
	size_t temp;

	if (lookup_mode == IP2PROXY_FILE_IO && handle != NULL) {
		fseek(handle, position - 1, SEEK_SET);
		temp = fread(&ret, 1, 1, handle);
		
		if (temp == 0) {
			return 0;
		}
	} else {
		ret = cache_shm[position - 1];
	}

	return ret;
}

uint8_t IP2Proxy_read8_row(uint8_t* buffer, uint32_t position, uint32_t mem_offset)
{
	uint8_t *cache_shm = memory_pointer;

	if (lookup_mode == IP2PROXY_FILE_IO) {
		return buffer[position];
	} else {
		return cache_shm[mem_offset + position - 1];
	}
}

char *IP2Proxy_read_string(FILE *handle, uint32_t position)
{
	uint8_t data[255];
	uint8_t size = 0;
	char* str = 0;
	uint8_t *cache_shm = memory_pointer;
	
	if (lookup_mode == IP2PROXY_FILE_IO && handle != NULL) {
		fseek(handle, position, 0);
		fread(&data, 255, 1, handle); // max size of string field + 1 byte for length
		size = data[0];
		str = (char *)malloc(size+1);
		memcpy(str, ((uint8_t*)data) + 1, size);
		str[size] = '\0'; // add null terminator
	} else {
		size = cache_shm[position];
		str = (char *)malloc(size + 1);
		memset(str, 0, size + 1);
		memcpy((void*) str, (void*)&cache_shm[position + 1], size);
	}
	return str;
}

float IP2Proxy_read_float(FILE *handle, uint32_t position)
{
	float ret = 0.0;
	uint8_t *cache_shm = memory_pointer;
	size_t temp;
	
#if defined(_SUN_) || defined(__powerpc__) || defined(__ppc__) || defined(__ppc64__) || defined(__powerpc64__)
	char *p = (char *) &ret;
	
	// for SUN SPARC, have to reverse the byte order
	if (lookup_mode == IP2PROXY_FILE_IO && handle != NULL) {
		fseek(handle, position - 1, SEEK_SET);
		
		temp = fread(p + 3, 1, 1, handle);
		
		if (temp == 0) {
			return 0.0;
		}

		temp = fread(p + 2, 1, 1, handle);
		
		if (temp == 0) {
			return 0.0;
		}

		temp = fread(p + 1, 1, 1, handle);
		
		if (temp == 0) {
			return 0.0;
		}

		temp = fread(p, 1, 1, handle);
		
		if (temp == 0) {
			return 0.0;
		}
	} else {
		*(p+3) = cache_shm[position - 1];
		*(p+2) = cache_shm[position];
		*(p+1) = cache_shm[position + 1];
		*(p) = cache_shm[position + 2];
	}
#else
	if (lookup_mode == IP2PROXY_FILE_IO && handle != NULL) {
		fseek(handle, position - 1, SEEK_SET);
		temp = fread(&ret, 4, 1, handle);
		
		if (temp == 0) {
			return 0.0;
		}
	} else {
		memcpy((void*) &ret, (void*)&cache_shm[position - 1], 4);
	}
#endif
	return ret;
}

float IP2Proxy_read_float_row(uint8_t* buffer, uint32_t position, uint32_t mem_offset)
{
	float ret = 0.0;
	uint8_t stuff[4];
	uint8_t *cache_shm = memory_pointer;
	
#if defined(_SUN_) || defined(__powerpc__) || defined(__ppc__) || defined(__ppc64__) || defined(__powerpc64__)
	char *p = (char *) &ret;
	
	// for SUN SPARC, have to reverse the byte order
	if (lookup_mode == IP2PROXY_FILE_IO) {
		uint8_t temp[4];
		memcpy(&temp, buffer + position, 4);
		stuff[0] = temp[3];
		stuff[1] = temp[2];
		stuff[2] = temp[1];
		stuff[3] = temp[0];
		memcpy(&ret, &stuff, 4);
	} else {
		*(p+3) = cache_shm[mem_offset + position - 1];
		*(p+2) = cache_shm[mem_offset + position];
		*(p+1) = cache_shm[mem_offset + position + 1];
		*(p) = cache_shm[mem_offset + position + 2];
	}
#else
	if (lookup_mode == IP2PROXY_FILE_IO) {
		memcpy(&stuff, buffer + position, 4);
		memcpy(&ret, &stuff, 4);
	} else {
		memcpy((void*) &ret, (void*)&cache_shm[mem_offset + position - 1], 4);
	}
#endif
	return ret;
}
