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
 *
 */

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <stdint.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <string.h>
#include <stdio.h>

#include "IP2Proxy.h"
#include "IP2Proxy_DB.h"

typedef struct ipv_t {
	uint32_t ipversion;
	uint32_t ipv4;
} ipv_t;

uint8_t PROXY_TYPE_POSITION[5]  = {0, 0, 2, 2, 2};
uint8_t COUNTRY_POSITION[5]     = {0, 2, 3, 3, 3};
uint8_t REGION_POSITION[5]      = {0, 0, 0, 4, 4};
uint8_t CITY_POSITION[5]        = {0, 0, 0, 5, 5};
uint8_t ISP_POSITION[5]         = {0, 0, 0, 0, 6};

static int IP2Proxy_initialize(IP2Proxy *loc);
static IP2ProxyRecord *IP2Proxy_new_record();
static uint32_t IP2Proxy_ip2no(char* ip);
static int IP2Proxy_ip_is_ipv4 (char* ipaddr);
static IP2ProxyRecord *IP2Proxy_get_record(IP2Proxy *loc, char *ip, uint32_t mode);
void str_replace(char *target, const char *needle, const char *replacement);
static int32_t openMemFlag = 0;

IP2Proxy *IP2Proxy_open(char *db){
	FILE *f;
	IP2Proxy *loc;

	if((f = fopen( db, "rb")) == NULL){
		printf("IP2Proxy library error in opening database %s.\n", db);
		return NULL;
	}

	loc = (IP2Proxy *) calloc(1, sizeof(IP2Proxy));
	loc->filehandle = f;

	IP2Proxy_initialize(loc);
	return loc;
}

IP2Proxy *IP2Proxy_open_csv(char *csv){
	IP2Proxy *loc;
	FILE *fp;
	char line[2048];
	char *delimiter = ";";
	char *token;

	int column = 0;

	if((fp = fopen(csv, "r")) == NULL){
        printf("Error when opening CSV file.");
		return NULL;
    }

	loc = (IP2Proxy *) calloc(1, sizeof(IP2Proxy));
	loc->filehandle = fp;
	loc->is_csv = 1;

	if(fgets(line, 512, fp) != NULL){
		rewind(fp);
		str_replace(line, "\",\"", ";");
		str_replace(line, "\"", "");

		token = strtok(line, delimiter);

		while(token != NULL){
			column++;
			token = strtok(NULL, delimiter);
		}
	}

	switch(column){
		case 4:
			loc->databasetype = 1;
			break;

		case 5:
			loc->databasetype = 2;
			break;

		case 7:
			loc->databasetype = 3;
			break;

		case 8:
			loc->databasetype = 4;
			break;
	}

	return loc;
}

// Description: This function to set the DB access type.
int32_t IP2Proxy_open_mem(IP2Proxy *loc, enum IP2Proxy_mem_type mtype)
{
	if(loc == NULL)
		return -1;

	// Once IP2Proxy_open_mem is called, it can not be called again till IP2Proxy_close is called
	if(openMemFlag != 0)
		return -1;
	openMemFlag = 1;

	if(mtype == IP2PROXY_FILE_IO)
	{
		return 0; //Just return, by default its IP2PROXY_FILE_IO
	}
	else if(mtype == IP2PROXY_CACHE_MEMORY)
	{
		return IP2Proxy_DB_set_memory_cache(loc->filehandle);
	}
	else if (mtype == IP2PROXY_SHARED_MEMORY)
	{
		return IP2Proxy_DB_set_shared_memory(loc->filehandle);
	}
	else
		return -1;
}

// Description: Close the IP2Proxy database file
uint32_t IP2Proxy_close(IP2Proxy *loc)
{
	openMemFlag = 0;
	if(loc != NULL)
	{
		IP2Proxy_DB_close(loc->filehandle);
		free(loc);
	}

	return 0;
}

// Description: Delete IP2Proxy shared memory if its present.
void IP2Proxy_delete_shm()
{
	IP2Proxy_DB_del_shm();
}

// Description: Startup
static int IP2Proxy_initialize(IP2Proxy *loc)
{
	loc->databasetype   = IP2Proxy_read8(loc->filehandle, 1);
	loc->databasecolumn = IP2Proxy_read8(loc->filehandle, 2);
	loc->databaseyear	= IP2Proxy_read8(loc->filehandle, 3);
	loc->databasemonth  = IP2Proxy_read8(loc->filehandle, 4);
	loc->databaseday   = IP2Proxy_read8(loc->filehandle, 5);

	loc->databasecount  = IP2Proxy_read32(loc->filehandle, 6);
	loc->databaseaddr   = IP2Proxy_read32(loc->filehandle, 10);
	loc->ipversion	  = IP2Proxy_read32(loc->filehandle, 14);

	loc->ipv4databasecount  = IP2Proxy_read32(loc->filehandle, 6);
	loc->ipv4databaseaddr   = IP2Proxy_read32(loc->filehandle, 10);

	loc->ipv4indexbaseaddr 	= IP2Proxy_read32(loc->filehandle, 22);

	return 0;
}

// Parses IPv[46] addresses and returns both the version of address
// and binary address used for searching
// You can implement domain name lookup here as well
// ipversion will be -1 on error (or something other than 4 or 6)
static ipv_t IP2Proxy_parse_addr(const char *addr)
{
	ipv_t parsed;
	if (IP2Proxy_ip_is_ipv4((char *)addr))
	{
		parsed.ipversion = 4;
		parsed.ipv4 = IP2Proxy_ip2no((char *)addr);
	}
	else
	{
		parsed.ipversion = -1;
	}

	return parsed;
}

// Description: Get country code
IP2ProxyRecord *IP2Proxy_get_country_short(IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, COUNTRYSHORT);
}

// Description: Get country name
IP2ProxyRecord *IP2Proxy_get_country_long(IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, COUNTRYLONG);
}

// Description: Get the name of state/region
IP2ProxyRecord *IP2Proxy_get_region(IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, REGION);
}

// Description: Get city name
IP2ProxyRecord *IP2Proxy_get_city (IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, CITY);
}

// Description: Get ISP name
IP2ProxyRecord *IP2Proxy_get_isp(IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, ISP);
}

// Description: Is Proxy
IP2ProxyRecord *IP2Proxy_is_proxy(IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, ISPROXY);
}

// Description: Get Proxy type
IP2ProxyRecord *IP2Proxy_get_proxy_type(IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, PROXYTYPE);
}

// Description: Get all records of an IP address
IP2ProxyRecord *IP2Proxy_get_all(IP2Proxy *loc, char *ip)
{
	return IP2Proxy_get_record(loc, ip, ALL);
}

// Description: fill the record fields with error message
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

	return record;
}

// Description: read the record data
static IP2ProxyRecord *IP2Proxy_read_record(IP2Proxy *loc, uint32_t rowaddr, uint32_t mode)
{
	uint8_t dbtype = loc->databasetype;
	FILE *handle = loc->filehandle;
	IP2ProxyRecord *record = IP2Proxy_new_record();
	record->is_proxy = "-1";

	if ((mode & ISPROXY) && (COUNTRY_POSITION[dbtype] != 0))
	{
		record->country_short = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (COUNTRY_POSITION[dbtype]-1)));

		if (strcmp(record->country_short, "-") == 0) {
			record->is_proxy = "0";
		}
		else{
			record->proxy_type = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (PROXY_TYPE_POSITION[dbtype]-1)));

			if (strcmp(record->proxy_type, "DCH") == 0) {
				record->is_proxy = "2";
			}
			else{
				record->is_proxy = "1";
			}
		}
	}
	else
	{
		record->is_proxy = "-1";
	}

	if ((mode & COUNTRYSHORT) && (COUNTRY_POSITION[dbtype] != 0))
	{
		record->country_short = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (COUNTRY_POSITION[dbtype]-1)));
	}
	else
	{
		record->country_short = strdup(NOT_SUPPORTED);
	}

	if ((mode & COUNTRYLONG) && (COUNTRY_POSITION[dbtype] != 0))
	{
		record->country_long = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (COUNTRY_POSITION[dbtype]-1))+3);
	}
	else
	{
		record->country_long = strdup(NOT_SUPPORTED);
	}

	if ((mode & REGION) && (REGION_POSITION[dbtype] != 0))
	{
		record->region = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (REGION_POSITION[dbtype]-1)));
	}
	else
	{
		record->region = strdup(NOT_SUPPORTED);
	}

	if ((mode & CITY) && (CITY_POSITION[dbtype] != 0))
	{
		record->city = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (CITY_POSITION[dbtype]-1)));
	}
	else
	{
		record->city = strdup(NOT_SUPPORTED);
	}

	if ((mode & ISP) && (ISP_POSITION[dbtype] != 0))
	{
		record->isp = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (ISP_POSITION[dbtype]-1)));
	}
	else
	{
		record->isp = strdup(NOT_SUPPORTED);
	}

	if ((mode & PROXYTYPE) && (PROXY_TYPE_POSITION[dbtype] != 0))
	{
		record->proxy_type = IP2Proxy_readStr(handle, IP2Proxy_read32(handle, rowaddr + 4 * (PROXY_TYPE_POSITION[dbtype]-1)));
	}
	else
	{
		record->proxy_type = strdup(NOT_SUPPORTED);
	}

	return record;
}

// Description: Get record for a IPv4 from database
static IP2ProxyRecord *IP2Proxy_get_ipv4_record(IP2Proxy *loc, char *ipstring, uint32_t mode, ipv_t parsed_ipv)
{
	FILE *handle = loc->filehandle;
	uint32_t ipno;
	uint32_t ipfrom;
	uint32_t ipto;

	ipno = parsed_ipv.ipv4;

	if (ipno == (uint32_t) MAX_IPV4_RANGE)
	{
		ipno = ipno - 1;
	}

	if(loc->is_csv == 1){
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

		while(fgets(line, 2048, handle) != NULL){
			str_replace(line, "\n", "");
			str_replace(line, "\",\"", ";");
			str_replace(line, "\"", "");

			token = strtok(line, delimiter);

			ipfrom = atoi(token);

			token = strtok(NULL, delimiter);

			ipto = atoi(token);

			if(ipno >= ipfrom && ipno <= ipto){
				is_found = 1;
				break;
			}
		}

		if(is_found == 0){
			record->country_short = "-";
			record->country_long = "-";
			record->region = "-";
			record->city = "-";
			record->isp = "-";
			record->is_proxy = "0";
			record->proxy_type = "-";

			return record;
		}

		switch(loc->databasetype){
			case 1:
				token = strtok(NULL, delimiter);
				record->country_short = strdup(token);

				token = strtok(NULL, delimiter);
				record->country_long = strdup(token);

				if(strcmp(record->country_short, "-") == 0){
					record->is_proxy = "0";
				}
				else{
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

				if(strcmp(record->country_short, "-") == 0){
					record->is_proxy = "0";
				}
				else if(strcmp(record->proxy_type, "DCH") == 0){
					record->is_proxy = "0";
				}
				else{
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


				if(strcmp(record->country_short, "-") == 0){
					record->is_proxy = "0";
				}
				else if(strcmp(record->proxy_type, "DCH") == 0){
					record->is_proxy = "0";
				}
				else{
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

				if(strcmp(record->country_short, "-") == 0){
					record->is_proxy = "0";
				}
				else if(strcmp(record->proxy_type, "DCH") == 0){
					record->is_proxy = "0";
				}
				else{
					record->is_proxy = "1";
				}

				return record;
		} 

		return NULL;
	}
	else{
		uint32_t baseaddr = loc->ipv4databaseaddr;
		uint32_t dbcolumn = loc->databasecolumn;
		uint32_t ipv4indexbaseaddr = loc->ipv4indexbaseaddr;

		uint32_t low = 0;
		uint32_t high = loc->ipv4databasecount;
		uint32_t mid = 0;

		if (ipv4indexbaseaddr > 0)
		{
			// use the index table 
			uint32_t ipnum1n2 = (uint32_t) ipno >> 16;
			uint32_t indexpos = ipv4indexbaseaddr + (ipnum1n2 << 3);

			low = IP2Proxy_read32(handle, indexpos);
			high = IP2Proxy_read32(handle, indexpos + 4);
		}

		while (low <= high)
		{
			mid = (uint32_t)((low + high) >> 1);
			ipfrom = IP2Proxy_read32(handle, baseaddr + mid * dbcolumn * 4);
			ipto 	= IP2Proxy_read32(handle, baseaddr + (mid + 1) * dbcolumn * 4);

			if ((ipno >= ipfrom) && (ipno < ipto))
			{
				return IP2Proxy_read_record(loc, baseaddr + (mid * dbcolumn * 4), mode);
			}
			else
			{
				if ( ipno < ipfrom )
				{
					high = mid - 1;
				}
				else
				{
					low = mid + 1;
				}
			}
		}
	}

	return NULL;
}

// Description: Get the location data
static IP2ProxyRecord *IP2Proxy_get_record(IP2Proxy *loc, char *ipstring, uint32_t mode)
{
	ipv_t parsed_ipv = IP2Proxy_parse_addr(ipstring);

	if (parsed_ipv.ipversion == 4)
	{
		//process IPv4
		return IP2Proxy_get_ipv4_record(loc, ipstring, mode, parsed_ipv);
	}
	else
	{
		return IP2Proxy_bad_record(INVALID_IPV4_ADDRESS);
	}
}

// Description: Initialize the record object
static IP2ProxyRecord *IP2Proxy_new_record()
{
	IP2ProxyRecord *record = (IP2ProxyRecord *) calloc(1, sizeof(IP2ProxyRecord));
	return record;
}

// Description: Free the record object
void IP2Proxy_free_record(IP2ProxyRecord *record)
{
	if (record == NULL)
	{
		return;
	}

	free(record);
}

// Description: Convert the IP address (v4) into number
static uint32_t IP2Proxy_ip2no(char* ipstring)
{
	uint32_t ip = inet_addr(ipstring);
	uint8_t *ptr = (uint8_t *) &ip;
	uint32_t a = 0;

	if (ipstring != NULL)
	{
		a =  (uint8_t)(ptr[3]);
		a += (uint8_t)(ptr[2]) * 256;
		a += (uint8_t)(ptr[1]) * 256 * 256;
		a += (uint8_t)(ptr[0]) * 256 * 256 * 256;
	}
	return a;
}


// Description: Check if this was an IPv4 address
static int IP2Proxy_ip_is_ipv4 (char* ipaddr)
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, ipaddr, &(sa.sin_addr));
}

// Description: Return API version as string
char *IP2Proxy_get_module_version(void)
{
	static char version[16];

	snprintf(version, sizeof(version), "%d.%d.%d", API_VERSION_MAJOR, API_VERSION_MINOR, API_VERSION_RELEASE);
	
	return version ;
}

char *IP2Proxy_get_database_version(IP2Proxy *loc){
	static char version[3];

	snprintf(version, sizeof(version), "%d", loc->databasetype);

	return version;
}

char *IP2Proxy_get_package_version(IP2Proxy *loc){
	static char version[8];

	snprintf(version, sizeof(version), "%02d%02d%02d", loc->databaseyear, loc->databasemonth, loc->databaseday);

	return version;
}

void str_replace(char *target, const char *needle, const char *replacement)
{
    char buffer[1024] = { 0 };
    char *insert_point = &buffer[0];
    const char *tmp = target;
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(replacement);

    while (1) {
        const char *p = strstr(tmp, needle);

        // walked past last occurrence of needle; copy remaining part
        if (p == NULL) {
            strcpy(insert_point, tmp);
            break;
        }

        // copy part before needle
        memcpy(insert_point, tmp, p - tmp);
        insert_point += p - tmp;

        // copy replacement string
        memcpy(insert_point, replacement, repl_len);
        insert_point += repl_len;

        // adjust pointers, move on
        tmp = p + needle_len;
    }

    // write altered string back to target
    strcpy(target, buffer);
}
