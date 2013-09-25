/*
* ** dnsmap - DNS Network Mapper by pagvac
* ** Copyright (C) 2010 gnucitizen.org
* ** Copyright (C) 2013 dzruyk
* **
* ** This program is free software; you can redistribute it and/or modify
* ** it under the terms of the GNU General Public License as published by
* ** the Free Software Foundation; either version 2 of the License, or
* ** (at your option) any later version.
* **
* ** This program is distributed in the hope that it will be useful,
* ** but WITHOUT ANY WARRANTY; without even the implied warranty of
* ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* ** GNU General Public License for more details.
* **
* ** You should have received a copy of the GNU General Public License
* ** along with this program; if not, write to the Free Software
* ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
* */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "dnsmap.h" // built-in subdomains list and define macros

// function prototypes
unsigned short int wildcarDetect(const char *, char *);
unsigned short int dodelay(unsigned short int);
unsigned short int isPrivateIP(char *);
unsigned short int isValidDomain(char *);
unsigned short int usesOpenDNS(char *);
unsigned short int isIPblacklisted(char *);

#define OUT_STD 0
#define OUT_REG 1
#define OUT_CSV 2

//some global variables
char *dnsname = NULL;
int use_wordlist = 0;
char wordlist_file[MAXSTRSIZE] = {'\0'};

int delay = 0;

int outfmt = OUT_STD;
char results_fn[MAXSTRSIZE] = {'\0'};
FILE *fp_out;

int filtered_ip_cnt = 0;
char filterIPs[5][INET_ADDRSTRLEN] = {{'\0'}};

/* FIXME: create context structure */
char wildcardIpStr[INET_ADDRSTRLEN] = {'\0'};
int found = 0; 
int ipCount = 0;
int intIPcount = 0;

void
generic_output(char *ipstr, int filter, int i, char *dom)
{
	if (i == 0) {
		++found;
		printf("%s\n", dom);

		if (outfmt == OUT_REG)
			fprintf(fp_out, "%s\n", dom);
		if (outfmt == OUT_CSV)
			fprintf(fp_out, "%s", dom);
	}
	printf("IP address #%d: %s\n", i + 1, ipstr);
	++ipCount;

	if (isPrivateIP(ipstr)) {
		printf("%s", INTIPWARN);
		++intIPcount;
	}
	if (!strcmp(ipstr, "127.0.0.1") && strcmp(wildcardIpStr, ipstr)) {
		printf("%s", SAMESITEXSSWARN);
	}
	if (outfmt == OUT_REG) {
		fprintf(fp_out, "IP address #%d: %s\n", i + 1, ipstr);
		if (isPrivateIP(ipstr) && strcmp(wildcardIpStr, ipstr))
			fprintf(fp_out, "%s", INTIPWARN);
		if (!strcmp(ipstr, "127.0.0.1") && strcmp(wildcardIpStr, ipstr))
			fprintf(fp_out, "%s", SAMESITEXSSWARN);
	}
	if (outfmt == OUT_CSV && strcmp(wildcardIpStr, ipstr))
		fprintf(fp_out, ",%s", ipstr);
}

//FIXME: FILTER is unnecessary, rewrite without it!
void
try_resolve_ipv4(char *dom)
{
	struct hostent *h;
	char ipstr[INET_ADDRSTRLEN] = {'\0'};
	int i, j;
	int filter = FALSE;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6; // AF_INET or AF_INET6 to force version
	hints.ai_socktype = SOCK_STREAM;

	h = gethostbyname(dom);

	if (!h || isIPblacklisted(inet_ntoa(*((struct in_addr *)h->h_addr_list[0]))))
		return;

	for (i = 0; h->h_addr_list[i]; ++i) {
		sprintf(ipstr, "%s", inet_ntoa(*((struct in_addr *)h->h_addr_list[i])));

		if (strcmp(wildcardIpStr, ipstr) == 0)
			continue;

		for (j = 0; j < filtered_ip_cnt; ++j) {
			if (strcmp(filterIPs[j], ipstr) == 0) { // filtered IP found
				// 1st IP of array - weird output formatting bug
				if (i != 0 && strcmp(wildcardIpStr, filterIPs[j])) {
					printf("\n");
					if (outfmt == OUT_REG || outfmt == OUT_CSV)
						fprintf(fp_out, "\n");
				}
				DEBUG_MSG("%s found and ignored\n", filterIPs[j]);
				filter = TRUE;
				if (h->h_addr_list[i + 1])
					++i;
				else
					break;
			}
		}
		if (filter == TRUE)
			continue;

		generic_output(ipstr, filter, i, dom);
	}

	if (strcmp(wildcardIpStr, ipstr) && filter == FALSE) {
		printf("\n");
		if (outfmt == OUT_REG || outfmt == OUT_CSV)
			fprintf(fp_out, "\n");
	}
}

void
try_resolve_ipv6(char *dom)
{
	struct addrinfo hints, *res, *p;
	char ipv6str[INET6_ADDRSTRLEN];
	int i;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6; // AF_INET or AF_INET6 to force version
	hints.ai_socktype = SOCK_STREAM;

	/* ipv6 code modded from www.kame.net */
	if (getaddrinfo(dom, NULL, &hints, &res) != 0)
		return;

	printf("%s\n", dom);
	++found;
	if (outfmt == OUT_REG)
		fprintf(fp_out, "%s\n", dom);
	if (outfmt == OUT_CSV)
		fprintf(fp_out, "%s", dom);
	for (p = res, i = 0; p ;p = p->ai_next, ++i) {
		void *addr;
		char *ipver;

		if (p->ai_family==AF_INET6) { // IPv6
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			addr = &(ipv6->sin6_addr);
			ipver = "IPv6";
		}
		/* convert the IP to a string and print it: */
		inet_ntop(p->ai_family, addr, ipv6str, sizeof(ipv6str));
		printf("%s address #%d: %s\n", ipver, i+1, ipv6str);
		++ipCount;
		if (outfmt == OUT_REG)
			fprintf(fp_out, "%s address #%d: %s\n", ipver, i+1, ipv6str);
		if (outfmt == OUT_CSV)
			fprintf(fp_out, ",%s", ipv6str);
	}
	printf("\n");
	if (outfmt == OUT_REG || outfmt == OUT_CSV)
		fprintf(fp_out, "\n");

	freeaddrinfo(res); // free the linked list
}

void
check_host(char *dom)
{
	try_resolve_ipv6(dom);
	try_resolve_ipv4(dom);

	/* User wants delay between DNS requests? */
	if (delay)
		dodelay(delay);
}

void
maybe_open_result_file()
{
	if (outfmt == OUT_STD)
		return;

	fp_out = fopen(results_fn, "a");
	if (!fp_out) {
		printf("[+] error creating results file on \"%s\"!\n\n", results_fn);
		exit(1);
	}
}

void
maybe_close_result_file()
{
	if (outfmt == OUT_STD)
		return;

	fclose(fp_out);
}

void
use_builtin_list()
{
	char dom[MAXSTRSIZE] = {'\0'};
	int i;

	maybe_open_result_file();

	printf("[+] searching (sub)domains for %s using built-in wordlist", dnsname);
	
	if (delay >= 1)
		printf("[+] using maximum random delay of %d ms between requests\n", delay);

	for (i = 0; i < (sizeof(sub) / MAXSUBSIZE); ++i) {
		strncpy(dom, sub[i], MAXSTRSIZE-strlen(dom) - 1);
		strncat(dom, ".", MAXSTRSIZE-strlen(dom) - 1);
		strncat(dom, dnsname, MAXSTRSIZE-strlen(dom) - 1);
		DEBUG_MSG("brute-forced domain: %s\n", dom);

		check_host(dom);
	}
	maybe_close_result_file();
}

void
use_user_list()
{
	FILE *fp;
	char dom[MAXSTRSIZE] = {'\0'};
	int i;

	printf("[+] searching (sub)domains for %s using %s\n", dnsname, wordlist_file);

	fp = fopen(wordlist_file, "r");
	if (!fp) {
		printf("%s\"%s\"!\n\n", "[+] error opening wordlist file ", wordlist_file);
		exit(1);
	}

	maybe_open_result_file();

	if (delay >= 1)
		printf("[+] using maximum random delay of %d ms between requests\n", delay);

	while (!feof(fp)) {
		//strncpy(dom, "", MAXSTRSIZE-strlen(dom)-1);
		for (i = 0; i < strlen(dom); ++i)
			dom[i] = '\0';
		fscanf(fp, "%100s", dom); // wordlist subdomain not allowed to be more than 100 chars
		DEBUG_MSG("lengh of dom: %d\n", strlen(dom));
		strncat(dom, ".", MAXSTRSIZE-strlen(dom) - 1);
		strncat(dom, dnsname, MAXSTRSIZE-strlen(dom) - 1);

		DEBUG_MSG("brute-forced domain: %s\n", dom);

		check_host(dom);
	}
	fclose(fp);
	maybe_close_result_file();
}

void
brute_domains()
{
	char invalidTldIpstr[INET_ADDRSTRLEN] = {'\0'};

	// openDNS detection
	if (usesOpenDNS(invalidTldIpstr))
		printf("%s", OPENDNSMSG);

	// wildcard detection
	wildcarDetect(dnsname, wildcardIpStr);

	if (strcmp(invalidTldIpstr, wildcardIpStr))
		printf("[+] warning: domain might use wildcards. "\
			"%s will be ignored from results\n", wildcardIpStr);

	if (!use_wordlist)
		use_builtin_list();
	else
		use_user_list();
}

void
parse_ip_filter(char *str)
{
	char *strP;
	int i;

	// filter out user-provided IP(s)
	for (filtered_ip_cnt = 1, i = 0; str[i] != '\0'; ++i)
		if (str[i] == ',')
			++filtered_ip_cnt;

	DEBUG_MSG("%d IP(s) to filter found\nParsing ...\n", filtered_ip_cnt);

	if (filtered_ip_cnt > 5) {
		printf(FILTIPINPUTERR);
		exit(1);
	}
	printf("[+] %d provided IP address(es) will be ignored from results: %s\n", filtered_ip_cnt, str);
	strP = strtok(str, ",");
	for (i = 0; strP;) {
		if (strlen(strP) < INET_ADDRSTRLEN) {
			strncpy(filterIPs[i], strP, INET_ADDRSTRLEN);
			DEBUG_MSG("%s\n", filterIPs[i]);
			++i;
		}
		strP = strtok(NULL, ",");
	}
}

void
parse_args(int argc, char *argv[])
{
	char *name;
	int i, opt;

	if (argc == 1) {
		printf("%s%s", USAGE, EXAMPLES);
		exit(1);
	}

	while ((opt = getopt(argc, argv, "w:r:c:d:i:")) != -1) {
		switch (opt) {
		case 'w':
			use_wordlist = TRUE;
			strncpy(wordlist_file, optarg, MAXSTRSIZE);
			break;
		case 'r':
			outfmt = OUT_REG;
			name = optarg;
			break;
		case 'c':
			outfmt = OUT_CSV;
			name = optarg;
			break;
		case 'd':
			delay = atoi(optarg);
			if (delay < 1 || delay > 300000) {
				printf("%s", DELAYINPUTERR);
				exit(1);
			}
			break;
		case 'i':
			parse_ip_filter(optarg);
			break;
		default:
			printf(FILTIPINPUTERR);
			exit(1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf("%s%s", USAGE, EXAMPLES);
		exit(1);
	}

	if (outfmt != OUT_STD) {
		strncpy(results_fn, name, MAXSTRSIZE - strlen(results_fn) - 1);
	}

	dnsname = argv[0];

	for (i = 0; dnsname[i]; ++i) // convert domain to lower case
		dnsname[i] = tolower(dnsname[i]);

	DEBUG_MSG("domain: %s\n", dnsname);

	if (!isValidDomain(dnsname)) {
		printf("%s", DOMAINERR);
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	unsigned long int start = 0, end = 0;

	printf("%s", BANNER);

	parse_args(argc, argv);

	start = (int)time(NULL);

	DEBUG_MSG("start time: %d\n", (int)start);

	brute_domains();

	printf("[+] %d (sub)domains and %d IP address(es) found\n", found, ipCount);

	if (intIPcount >= 1)
		printf("[+] %d internal IP address(es) disclosed\n", intIPcount);

	if (outfmt != OUT_STD)
		printf("[+] %s-format results can be found on %s\n",
		    outfmt == OUT_REG ? "regular" : "csv", results_fn);

	end = (int)time(NULL);

	printf("[+] completion time: %lu second(s)\n", end - start);

	return 0;
}

/* return TRUE and set wildcard_ip string if domain wildcards are enabled */
unsigned short int
wildcarDetect(const char *dom, char *wildcard_ip)
{
	char strTmp[30] = {'\0'}, s[MAXSTRSIZE] = {'\0'};
	unsigned short int i = 0, n = 0, max = 0;
	struct hostent *h;

	srand(time(NULL));
	max = rand() % 20;

	/* max should be between 10 and 20 */
	if (max < 10)
		max += 10;

	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554

	memset(s, 0, sizeof(s));

	for (i = 0; i < max; ++i) {
		n = rand() % 10;
		sprintf(strTmp, "%d", n);
		strncat(s, strTmp, MAXSTRSIZE-strlen(s)-1);
	}
	strncat(s, ".", MAXSTRSIZE-strlen(s)-1);
	strncat(s, dom, MAXSTRSIZE-strlen(s)-1);
	DEBUG_MSG("random subdomain for wildcard testing: %s\n", s);

	// random subdomain resolves, thus wildcards are enabled
	h = gethostbyname(s); // replace with getaddrinfo() ?
	if (h) {
		sprintf(wildcard_ip, "%s", inet_ntoa(*((struct in_addr *)h->h_addr_list[0])));
		DEBUG_MSG("wildcard domain\'s IP address: %s\n", wildcard_ip);
		return TRUE;
	}
	else
		return FALSE;
}

// return number of delay delayed
unsigned short int
dodelay(unsigned short int maxmillisecs)
{
	unsigned short int n = 0;

	srand(time(NULL));
	n = rand() % maxmillisecs;
	++n;
	maxmillisecs = n;
	DEBUG_MSG("sleeping %d ms ...\n", maxmillisecs);
	usleep(maxmillisecs * 1000);

	return maxmillisecs;
}

//FIXME: Is we have way to compress code?
// return true if IP addr is internal (RFC1918)
unsigned short int
isPrivateIP(char *ip)
{
	char classB[][8] = {"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31."};

	unsigned short int i = 0, j = 0;
	size_t len = strlen(ip);

	// shortest: 0.0.0.0 - 8 chars inc \0
	// longest: 255.255.255.255 - 16 chars inc \0
	if (len < 8 || len > 16)
		return FALSE;
	// ip addr must have three period signs
	for (i = 0, j = 0; i < len; ++i) {
		if (ip[i] == '.')
			++j;
	}
	if (j != 3 || ip[0] == '.' || ip[len-1] == '.')
		return FALSE;

	// 10.0.0.0 - 10.255.255.255 (10/8 prefix)
	if (strncmp(ip, "10.", 3) == 0)
		return TRUE;

	// 192.168.0.0 - 192.168.255.255 (192.168/16 prefix)
	else if(strncmp(ip, "192.168.", 8) == 0)
		return TRUE;


	// 172.16.0.0 - 172.31.255.255  (172.16/12 prefix)
	for (i = 0; i < sizeof(classB) / 8; ++i) {
		if (strncmp(ip, classB[i], 7) == 0)
			return TRUE;
	}
	return FALSE;
}

//FIXME: check me!
// return true if domain is valid, false otherwise
unsigned short int
isValidDomain(char *d)
{
	unsigned int i = 0, j = 0;
	char *tld;
	size_t len;
	char strTmp[30] = {'\0'}, s[MAXSTRSIZE] = {'\0'};
	unsigned short int n = 0, max = 0;

	struct hostent *h;

	if (strlen(d) < 4) // smallest possible domain provided. e.g. a.pl
		return FALSE;
	if (!strstr(d, ".")) // target domain must have at least one dot. e.g. target.va, branch.target.va
		return FALSE;
	tld = strstr(d, ".");
	tld = tld + 1;
	while (strstr(tld, ".")) {
		tld = strstr(tld, ".");
		tld = tld + 1;
	}
	DEBUG_MSG("tld\'s length: %d\n", strlen(tld));
	DEBUG_MSG("dom: %s tld: %s\n", d, tld);
	if ((strlen(tld) < 2) || (strlen(tld) > 6)) // tld must be between 2-6 char. e.g. .museum, .uk
		return FALSE;

	// valid domain can only contain digits, letters, dot (.) and dash symbol (-)
	len = strlen(d);
	for (i = 0;i < len; ++i) {
		if (!(d[i] >= '0' && d[i] <= '9') &&
			!(d[i] >= 'a' && d[i] <= 'z') &&
			!(d[i] >= 'A' && d[i] <= 'Z') &&
			!(d[i] >= '-' && d[i] <= '.'))
			return FALSE;
	}

	srand(time(NULL));
	max = rand() % 20;

	/* max should be between 10 and 20 */
	if (max < 10)
		max += 10;

	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554

	for (i = 0; i < max; ++i) {
		n = rand( )% 10;
		sprintf(strTmp, "%d", n);
		if (i == 0)
			strncpy(s, strTmp, MAXSTRSIZE-strlen(s)-1);
		else
			strncat(s, strTmp, MAXSTRSIZE-strlen(s)-1);
	}
	strncat(s, ".", MAXSTRSIZE - strlen(s) - 1);
	strncat(s, d, MAXSTRSIZE - strlen(s) - 1);
	DEBUG_MSG("random subdomain for wildcard testing: %s\n", s);

	// some domains like proboards.com return more than 1 IP address
	// when resolving random subdomains (wildcards are enabled)
	h = gethostbyname(s);
	if (h) {
		for (j = 0; h->h_addr_list[j]; ++j)
			inet_ntoa(*((struct in_addr *)h->h_addr_list[j]));
		if (j > 1) {
			DEBUG_MSG("wildcard domain\'s number of IP address(es): %d"
					" (this causes dnsmap to produce false positives)\n", j);
			return FALSE;
		}
	}

	return TRUE;
}

//FIXME: rly need to hardcode blacklist addresses?
// return true if IP is blacklisted, false otherwise
unsigned short int
isIPblacklisted(char *ip)
{
	int i;
	// add you own blacklisted IP addresses here if dnsmap is producing false positives.
	// this could be caused by your ISP returning a captive portal search page when
	// when requesting invalid domains on your browser
	char ips[][INET_ADDRSTRLEN] = {
					"81.200.64.50",
					"67.215.66.132",
					"1.2.3.4",
					"0.0.0.0"	// add your false positive IPs here
	};

	for (i = 0; i < (sizeof(ips) / INET_ADDRSTRLEN); ++i) {
		if (!strcmp(ips[i], ip))
			return TRUE;
	}

	return FALSE;
}


//FIXME: almost same as wildcarDetect. Need to rewrite!
// return true if usage of public DNS server is detected
// Note: right now this function only detects openDNS, but might be
// updated in the future to detect other common public DNS servers
unsigned short int
usesOpenDNS(char *ipstr)
{
	char strTmp[30] = {'\0'}, s[MAXSTRSIZE] = {'\0'}, dummyLTD[4] = {"xyz"}/*, ipstr[INET_ADDRSTRLEN] = {'\0'}*/;
	char ips[][INET_ADDRSTRLEN] = {"67.215.65.132"};
	unsigned short int i = 0, j = 0, n = 0, max = 0;
	struct hostent *h;

	srand(time(NULL));
	max = rand() % 20;

	// max should be between 10 and 20
	if (max < 10)
		max += 10;

	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554

	memset(s, 0, sizeof(s));

	for (i = 0; i < max; ++i) {
		n = rand() % 10;
		sprintf(strTmp, "%d", n);
		strncat(s, strTmp, MAXSTRSIZE-strlen(s) - 1);
	}

	strncat(s, ".", MAXSTRSIZE-strlen(s) - 1);
	strncat(s, dummyLTD, MAXSTRSIZE-strlen(s) - 1);
	DEBUG_MSG("random domain for public DNS testing: %s\n", s);

	// random invalid domain resolves, thus public DNS in use
	h = gethostbyname(s);
	if (!h)
		return FALSE;

	for (i = 0; h->h_addr_list[i]; ++i) {
		sprintf(ipstr, "%s", inet_ntoa(*((struct in_addr *)h->h_addr_list[i])));
		DEBUG_MSG("public DNS server\'s default IP address #%d: %s\n", i + 1, ipstr);
		for (j = 0;i < (sizeof(ips) / INET_ADDRSTRLEN); ++j) {
				if (!strcmp(ips[i], ipstr))
					return TRUE;
		}
	}
	return TRUE;
}
