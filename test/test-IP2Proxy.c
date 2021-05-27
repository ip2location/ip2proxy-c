#include <IP2Proxy.h>
#include <string.h>

int main ()
{
	IP2ProxyRecord *record = NULL;

	/*
	Lookup by CSV file (Slower)
	*/
	/*IP2Proxy *IP2ProxyObj = IP2Proxy_open_csv("../data/SAMPLE.CSV");

	if (IP2ProxyObj == NULL){
		printf("Please install the database in correct path.\n");
		return -1;
	}*/

	/*
	Lookup by BIN database (Faster)
	*/
	IP2Proxy *IP2ProxyObj = IP2Proxy_open("../data/SAMPLE.BIN");

	if (IP2ProxyObj == NULL) {
		printf("Please install the database in correct path.\n");
		return -1;
	}

	/*
	Lookup by BIN database in memory (Fastest)
	WARNING: Please make sure your machine have enough memory to use this method.
	*/
	/*if(IP2Proxy_set_lookup_mode(IP2ProxyObj, IP2PROXY_SHARED_MEMORY) == -1)
	{
		fprintf(stderr, "Call to IP2Proxy_set_lookup_mode failed\n");
		return -1;
	}
	*/

	record = IP2Proxy_get_all(IP2ProxyObj, "8.8.8.8");

	fprintf(stdout, "Module Version: %s\n", IP2Proxy_version_string());
	fprintf(stdout, "Database Version: %s\n\n", IP2Proxy_get_database_version(IP2ProxyObj));
	fprintf(stdout, "Country Code: %s\n", record->country_short);
	fprintf(stdout, "Country Name: %s\n", record->country_long);
	fprintf(stdout, "Region: %s\n", record->region);
	fprintf(stdout, "City: %s\n", record->city);
	fprintf(stdout, "ISP: %s\n", record->isp);
	fprintf(stdout, "Is Proxy: %s\n", record->is_proxy);
	fprintf(stdout, "Proxy Type: %s\n", record->proxy_type);
	fprintf(stdout, "Domain: %s\n", record->domain);
	fprintf(stdout, "Usage Type: %s\n", record->usage_type);
	fprintf(stdout, "ASN: %s\n", record->asn);
	fprintf(stdout, "AS: %s\n", record->as_);
	fprintf(stdout, "Last Seen: %s\n", record->last_seen);
	fprintf(stdout, "Threat: %s\n", record->threat);
	fprintf(stdout, "Provider: %s\n", record->provider);

	IP2Proxy_close(IP2ProxyObj);
	IP2Proxy_free_record(record);

	return 1;
}

