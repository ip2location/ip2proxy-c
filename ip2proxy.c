#include <string.h>
#include <stdbool.h>
#include <IP2Proxy.h>

static void print_usage(const char *argv0)
{
	printf(
"ip2proxy -p [IP ADDRESS] -d [IP2PROXY BIN DATA PATH] [OPTIONS]\n"
"	-b, --bin-version\n"
"		Print the IP2Proxy BIN database version.\n"
"\n"
"	-d, --data-file\n"
"		Specify the path of IP2Proxy BIN data file.\n"
"\n"
"	-e, --field\n"
"		Output the field data.\n"
"		Field name includes:\n"
"			is_proxy\n"
"			Check wether if an IP address was a proxy.\n"
"			* -1 - Error\n"
"			*  0 - Not a proxy\n"
"			*  1 - Is a proxy\n"
"			*  2 - A data center IP address\n"
"\n"
"			proxy_type\n"
"			Proxy type.\n"
"\n"
"			country_code\n"
"			Two-character country code based on ISO 3166.\n"
"\n"
"			country_name\n"
"			Country name based on ISO 3166.\n"
"\n"
"			region_name\n"
"			Region or state name.\n"
"\n"
"			city_name\n"
"			City name.\n"
"\n"
"			isp\n"
"			Internet Service Provider or company's name.\n"
"\n"
"			domain\n"
"			Internet domain name associated with IP address range.\n"
"\n"
"			usage_type\n"
"			Usage type classification of ISP or company,\n"
"			* (COM) Commercial\n"
"			* (ORG) Organization\n"
"			* (GOV) Government\n"
"			* (MIL) Military\n"
"			* (EDU) University/College/School\n"
"			* (LIB) Library\n"
"			* (CDN) Content Delivery Network\n"
"			* (ISP) Fixed Line ISP\n"
"			* (MOB) Mobile ISP\n"
"			* (DCH) Data Center/Web Hosting/Transit\n"
"			* (SES) Search Engine Spider\n"
"			* (RSV) Reserved\n"
"\n"
"			asn\n"
"			Autonomous system number (ASN).\n"
"\n"
"			as\n"
"			Autonomous system (AS) name.\n"
"\n"
"			last_seen\n"
"			Proxy last seen in days.\n"
"\n"
"			threat\n"
"			Security threat reported.\n"
"			* (SPAM) Email and forum spammers\n"
"			* (SCANNER) Network security scanners\n"
"			* (BOTNET) Malware infected devices\n"
"\n"
"			provider\n"
"			Name of VPN provider if available.\n"
"\n"
"	-f, --format\n"
"	Output format. Supported format:\n"
"		- csv (default)\n"
"		- tab\n"
"		- xml\n"
"\n"
"	-h, -?, --help\n"
"	Display the help.\n"
"\n"
"	-i, --input-file\n"
"	Specify an input file of IP address list, one IP per row.\n"
"\n"
"	-n, --no-heading\n"
"	Suppress the heading display.\n"
"\n"
"	-o, --output-file\n"
"	Specify an output file to store the lookup results.\n"
"\n"
"	-p, --ip\n"
"	Specify an IP address query (Supported IPv4 and IPv6 address).\n"
"\n"
"	-v, --version\n"
"	Print the version of the IP2Proxy version.\n");
}

static void print_version()
{
	printf("IP2Proxy version 4.1.2\n");
}

static void print_footer(FILE *fout, const char *field, const char *format)
{
	if (strcmp(format, "XML") == 0) {
		fprintf(fout, "</xml>\n");
		return;
	}
}

static void print_header(FILE *fout, const char *field, const char *format)
{
	const char *start = field;
	const char *end = strchr(start, ',');
	int first = 1;

	if (strcmp(format, "XML") == 0) {
		fprintf(fout, "<xml>\n");
		return;
	}

#define WRITE_HEADER(field_name)  \
		if (strncmp(start, field_name, end - start) == 0) { \
			if (strcmp(format, "CSV") == 0) { \
				if (!first) { \
					fprintf(fout, ","); \
				} \
				fprintf(fout, "\"%s\"", field_name); \
			} else if (strcmp(format, "TAB") == 0) { \
				if (!first) { \
					fprintf(fout, "\t"); \
				} \
				fprintf(fout, "%s", field_name); \
			} \
			first = 0; \
		}
	for (;;) {
		if (end == NULL) {
			end = start + strlen(start);
		}

		WRITE_HEADER("ip");
		WRITE_HEADER("is_proxy");
		WRITE_HEADER("proxy_type");
		WRITE_HEADER("country_code");
		WRITE_HEADER("country_name");
		WRITE_HEADER("region_name");
		WRITE_HEADER("city_name");
		WRITE_HEADER("isp");
		WRITE_HEADER("domain");
		WRITE_HEADER("usage_type");
		WRITE_HEADER("as_number");
		WRITE_HEADER("as_name");
		WRITE_HEADER("last_seen");
		WRITE_HEADER("threat");
		WRITE_HEADER("provider");

		if (*end == ',') {
			start = end + 1;
			end = strchr(start, ',');
		} else {
			break;
		}
	}
	fprintf(fout, "\n");
}


static void print_record(FILE *fout, const char *field, IP2ProxyRecord *record, const char *format, const char *ip)
{
	const char *start = field;
	const char *end = strchr(start, ',');
	int first = 1;

	if (strcmp(format, "XML") == 0) {
		fprintf(fout, "<row>");
	}

#define WRITE_FIELD(field_name, field)  \
		if (strncmp(start, field_name, end - start) == 0) { \
			const char *value = field; \
			if (strcmp(value, NOT_SUPPORTED) == 0) { \
				value = "N/A"; \
			} \
			if (strcmp(format, "XML") == 0) { \
				fprintf(fout, "<%s>%s</%s>", field_name, value, field_name); \
			} else if (strcmp(format, "CSV") == 0) { \
				if (!first) { \
					fprintf(fout, ","); \
				} \
				fprintf(fout, "\"%s\"", value); \
			} else if (strcmp(format, "TAB") == 0) { \
				if (!first) { \
					fprintf(fout, "\t"); \
				} \
				fprintf(fout, "%s", value); \
			} \
			first = 0; \
		}
#define WRITE_FIELDF(field_name, field)  \
		if (strncmp(start, field_name, end - start) == 0) { \
			if (strcmp(format, "XML") == 0) { \
				fprintf(fout, "<%s>%f</%s>", field_name, field, field_name); \
			} else if (strcmp(format, "CSV") == 0) { \
				if (!first) { \
					fprintf(fout, ","); \
				} \
				fprintf(fout, "\"%f\"", field); \
			} else if (strcmp(format, "TAB") == 0) { \
				if (!first) { \
					fprintf(fout, "\t"); \
				} \
				fprintf(fout, "%f", field); \
			} \
			first = 0; \
		}


	for (;;) {
		if (end == NULL) {
			end = start + strlen(start);
		}

		WRITE_FIELD("ip", ip);
		WRITE_FIELD("is_proxy", record->is_proxy);
		WRITE_FIELD("proxy_type", record->proxy_type);
		WRITE_FIELD("country_code", record->country_short);
		WRITE_FIELD("country_name", record->country_long);
		WRITE_FIELD("region_name", record->region);
		WRITE_FIELD("city_name", record->city);
		WRITE_FIELD("isp", record->isp);
		WRITE_FIELD("domain", record->domain);
		WRITE_FIELD("usage_type", record->usage_type);
		WRITE_FIELD("as_number", record->asn);
		WRITE_FIELD("as_name", record->as_);
		WRITE_FIELD("last_seen", record->last_seen);
		WRITE_FIELD("threat", record->threat);
		WRITE_FIELD("provider", record->provider);

		if (*end == ',') {
			start = end + 1;
			end = strchr(start, ',');
		} else {
			break;
		}
	}
	if (strcmp(format, "XML") == 0) {
		fprintf(fout, "</row>");
	}
	fprintf(fout, "\n");
}

int main(int argc, char *argv[])
{
	int i;
	char *data_file = NULL;

	const char *input_file = NULL;
	const char *output_file = NULL;
	const char *ip = NULL;
	const char *format = "CSV";
	const char *field = NULL;
	int no_heading = 0;
	bool print_bin_version = false;
	IP2Proxy *obj = NULL;
	IP2ProxyRecord *record = NULL;
	FILE *fout = stdout;

	field = "ip,is_proxy,proxy_type,country_code,country_name,region_name,city_name,isp,domain,as_number,as_name,last_seen,threat,provider";

	for (i = 1; i < argc; i++) {
		const char *argvi = argv[i];

		if (strcmp(argvi, "-d") == 0 || strcmp(argvi, "--data-file") == 0) {
			if (i + 1 < argc) {
				data_file = argv[++i];
			}
		} else if (strcmp(argvi, "-i") == 0 || strcmp(argvi, "--input-file") == 0) {
			if (i + 1 < argc) {
				input_file = argv[++i];
			}
		} else if (strcmp(argvi, "-b") == 0 || strcmp(argvi, "--bin-version") == 0) {
			print_bin_version = true;
		} else if (strcmp(argvi, "-p") == 0 || strcmp(argvi, "--ip") == 0) {
			if (i + 1 < argc) {
				ip = argv[++i];
			}
		} else if (strcmp(argvi, "-o") == 0 || strcmp(argvi, "--output-file") == 0) {
			if (i + 1 < argc) {
				output_file = argv[++i];
			}
		} else if (strcmp(argvi, "-f") == 0 || strcmp(argvi, "--format") == 0) {
			if (i + 1 < argc) {
				format = argv[++i];
			}
		} else if (strcmp(argvi, "-h") == 0 || strcmp(argvi, "-?") == 0 || strcmp(argvi, "--help") == 0) {
			print_usage(argv[0]);
			return 0;
		} else if (strcmp(argvi, "-v") == 0 || strcmp(argvi, "--version") == 0) {
			print_version();
			return 0;
		} else if (strcmp(argvi, "-e") == 0 || strcmp(argvi, "--field") == 0) {
			if (i + 1 < argc) {
				field = argv[++i];
			}
		} else if (strcmp(argvi, "-n") == 0 || strcmp(argvi, "--no-heading") == 0) {
			no_heading = 1;
		}
	}

	if (strcmp(format, "CSV") != 0 && strcmp(format, "XML") != 0 && strcmp(format, "TAB") != 0) {
		fprintf(stderr, "Invalid format %s, supported formats: CSV, XML, TAB\n", format);
		exit(-1);
	}

	if (data_file == NULL) {
		fprintf(stderr, "Datafile is absent\n");
		exit(-1);
	}

	obj = IP2Proxy_open((char *)data_file);
	if (obj == NULL) {
		fprintf(stderr, "Failed to open BIN database %s\n", data_file);
		exit(-1);
	}

	if (print_bin_version) {
		printf("BIN version %s\n", IP2Proxy_get_package_version(obj));
		exit(0);
	}

	if (output_file != NULL) {
		fout = fopen(output_file, "w");
		if (fout == NULL) {
			fprintf(stderr, "Failed to open output file %s\n", output_file);
			exit(-1);
		}
	}

	if (!no_heading) {
		print_header(fout, field, format);
	}

	if (ip != NULL) {
		record = IP2Proxy_get_all(obj, (char *)ip);
		print_record(fout, field, record, format, ip);
		IP2Proxy_free_record(record);
	}

	if (input_file != NULL) {
		char *line = NULL;
		size_t n;
		ssize_t len;
		FILE *fin = fopen(input_file, "r");

		if (fin == NULL) {
			fprintf(stderr, "Failed to open input file %s\n", input_file);
			exit(-1);
		}

		while ((len = getline(&line, &n, fin)) != -1) {
			if (line[len - 1] == '\n') {
				line[--len] = '\0';
			}
			if (line[len - 1] == '\r') {
				line[--len] = '\0';
			}
			record = IP2Proxy_get_all(obj, line);
			print_record(fout, field, record, format, line);
			IP2Proxy_free_record(record);
		}

		fclose(fin);
	}

	if (!no_heading) {
		print_footer(fout, field, format);
	}

	IP2Proxy_close(obj);

	return 0;
}
