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
unsigned short int is_private_ip(char *);
unsigned short int isValidDomain(char *);

enum {
	OUT_STD = 0,
	OUT_REG = 1,
	OUT_CSV = 2
};

//some global variables
char *dnsname = NULL;
int use_wordlist = 0;
char wordlist_file[MAXSTRSIZE] = {'\0'};

int delay = 0;
int threads = 1;

int outfmt = OUT_STD;
char results_fn[MAXSTRSIZE] = {'\0'};
FILE *fp_out;

/* FIXME: create context structure */
char wildcardIpStr[INET_ADDRSTRLEN] = {'\0'};
int found = 0;
int ipCount = 0;
int intIPcount = 0;

void
output_eol()
{
	printf("\n");
	if (outfmt == OUT_REG || outfmt == OUT_CSV)
		fprintf(fp_out, "\n");
}

void
output_domain(char *dom)
{
	printf("%s\n", dom);
	if (outfmt == OUT_REG)
		fprintf(fp_out, "%s\n", dom);
	if (outfmt == OUT_CSV)
		fprintf(fp_out, "%s", dom);
}

void
output_ip(char *ipstr, char *ipver, int i)
{
	printf("%s address #%d: %s\n", ipver, i + 1, ipstr);

	if (is_private_ip(ipstr)) {
		printf("%s", INTIPWARN);
		++intIPcount;
	}
	if (!strcmp(ipstr, "127.0.0.1") && strcmp(wildcardIpStr, ipstr)) {
		printf("%s", SAMESITEXSSWARN);
	}
	if (outfmt == OUT_REG) {
		fprintf(fp_out, "%s address #%d: %s\n", ipver, i + 1, ipstr);
		if (is_private_ip(ipstr) && strcmp(wildcardIpStr, ipstr))
			fprintf(fp_out, "%s", INTIPWARN);
		if (!strcmp(ipstr, "127.0.0.1") && strcmp(wildcardIpStr, ipstr))
			fprintf(fp_out, "%s", SAMESITEXSSWARN);
	}
	if (outfmt == OUT_CSV && strcmp(wildcardIpStr, ipstr))
		fprintf(fp_out, ",%s", ipstr);
}

void
try_resolve(char *dom)
{
	struct addrinfo hints, *res, *p;
	char ipstr[INET6_ADDRSTRLEN];
	int i;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(dom, NULL, &hints, &res) != 0)
		return;

	++found;

	output_domain(dom);

	for (p = res, i = 0; p ;p = p->ai_next, ++i) {
		void *addr;
		char *ipver;

		if (p->ai_family==AF_INET6) {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;

			addr = &(ipv6->sin6_addr);
			ipver = "IPv6";
		} else {
			struct  sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);

			ipver = "IPv4";
		}
		inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));

		if (strcmp(wildcardIpStr, ipstr) == 0)
			continue;

		++ipCount;

		output_ip(ipstr, ipver, i);
	}

	output_eol();

	freeaddrinfo(res);
}

void
check_host(char *dom)
{
	try_resolve(dom);

	if (delay)
		dodelay(delay);
}

void
maybe_open_result_file()
{
	if (outfmt == OUT_STD)
		return;

	fp_out = fopen(results_fn, "a");
	if (!fp_out)
		error(1, "[+] error creating results file on \"%s\"!\n\n", results_fn);
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

	printf("[+] searching (sub)domains for %s using built-in wordlist\n", dnsname);

	if (delay >= 1)
		printf("[+] using maximum random delay of %d ms between requests\n", delay);

	for (i = 0; i < (sizeof(sub) / MAXSUBSIZE); ++i) {
		strncpy(dom, sub[i], MAXSTRSIZE-strlen(dom) - 1);
		strncat(dom, ".", MAXSTRSIZE-strlen(dom) - 1);
		strncat(dom, dnsname, MAXSTRSIZE-strlen(dom) - 1);
		DEBUG_MSG("brute-forced domain: %s\n", dom);

		check_host(dom);
	}
}

void
use_user_list()
{
	FILE *fp;
	char dom[MAXSTRSIZE] = {'\0'};
	int i;

	printf("[+] searching (sub)domains for %s using %s\n", dnsname, wordlist_file);

	fp = fopen(wordlist_file, "r");
	if (!fp)
		error(1, "%s\"%s\"!\n\n", "[+] error opening wordlist file ", wordlist_file);

	if (delay >= 1)
		printf("[+] using maximum random delay of %d ms between requests\n", delay);

	while (!feof(fp)) {
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
}

void
brute_domains()
{
	char invalidTldIpstr[INET_ADDRSTRLEN] = {'\0'};

	// wildcard detection
	wildcarDetect(dnsname, wildcardIpStr);

	if (strcmp(invalidTldIpstr, wildcardIpStr))
		printf("[+] warning: domain might use wildcards. "\
			"%s will be ignored from results\n", wildcardIpStr);

	maybe_open_result_file();

	if (!use_wordlist)
		use_builtin_list();
	else
		use_user_list();

	maybe_close_result_file();
}

void
parse_args(int argc, char *argv[])
{
	char *name;
	int i, opt;

	if (argc == 1)
		error(1, "%s%s", USAGE, EXAMPLES);

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
			if (delay < 1 || delay > 300000)
				error(1, "%s", DELAYINPUTERR);
			break;
		case 't':
			threads = atoi(optarg);
			if (threads < 1 || threads > 512)
				error(1, "number of threads must be between 1 and 512");
		default:
			error(1, FILTIPINPUTERR);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		error(1, "%s%s", USAGE, EXAMPLES);

	if (outfmt != OUT_STD) {
		strncpy(results_fn, name, MAXSTRSIZE - strlen(results_fn) - 1);
	}

	dnsname = argv[0];

	for (i = 0; dnsname[i]; ++i) // convert domain to lower case
		dnsname[i] = tolower(dnsname[i]);

	DEBUG_MSG("domain: %s\n", dnsname);

	if (!isValidDomain(dnsname))
		error(1, "%s", DOMAINERR);
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

void
gen_rand_domain(char *dst, const char *dom)
{
	char strTmp[30] = {'\0'};
	unsigned short int i, max;

	srand(time(NULL));
	max = rand() % 20;

	/* max should be between 10 and 20 */
	if (max < 10)
		max += 10;

	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554

	memset(dst, 0, sizeof(dst));

	for (i = 0; i < max; ++i) {
		int n;

		n = rand() % 10;
		sprintf(strTmp, "%d", n);
		strncat(dst, strTmp, MAXSTRSIZE-strlen(dst)-1);
	}
	strncat(dst, ".", MAXSTRSIZE - strlen(dst) - 1);
	strncat(dst, dom, MAXSTRSIZE - strlen(dst) - 1);
}

/* return TRUE and set wildcard_ip string if domain wildcards are enabled */
unsigned short int
wildcarDetect(const char *dom, char *wildcard_ip)
{
	char s[MAXSTRSIZE] = {'\0'};
	struct hostent *h;

	gen_rand_domain(s, dom);

	DEBUG_MSG("random subdomain for wildcard testing: %s\n", s);

	// random subdomain resolves, thus wildcards are enabled
	h = gethostbyname(s); // replace with getaddrinfo() ?
	if (h == NULL)
		return FALSE;

	sprintf(wildcard_ip, "%s", inet_ntoa(*((struct in_addr *)h->h_addr_list[0])));
	DEBUG_MSG("wildcard domain\'s IP address: %s\n", wildcard_ip);

	return TRUE;
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

#define MAXSTRLEN 10
//FIXME: need add IPv6 support
// return true if IP addr is internal (RFC1918)
unsigned short int
is_private_ip(char *ip)
{
	char private_ips[][MAXSTRLEN] = {"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.",
		"10.",
		"192.168."};
	unsigned short int i = 0, j = 0;
	size_t len = strlen(ip);

	// ip addr must have three period signs
	for (i = 0, j = 0; i < len; ++i) {
		if (ip[i] == '.')
			++j;
	}
	if (j != 3 || ip[0] == '.' || ip[len-1] == '.')
		return FALSE;

	for (i = 0; i < sizeof(private_ips) / MAXSTRLEN; ++i) {
		if (strncmp(ip, private_ips[i], strlen(private_ips[i])) == 0)
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
	size_t len;
	char s[MAXSTRSIZE] = {'\0'};

	struct hostent *h;

	if (strlen(d) < 4) // smallest possible domain provided. e.g. a.pl
		return FALSE;
	if (!strstr(d, ".")) // target domain must have at least one dot. e.g. target.va, branch.target.va
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

	gen_rand_domain(s, d);
	DEBUG_MSG("random subdomain for wildcard testing: %s\n", s);

	// some domains like proboards.com return more than 1 IP address
	// when resolving random subdomains (wildcards are enabled)
	h = gethostbyname(s);
	if (h == NULL)
		return TRUE;
	for (j = 0; h->h_addr_list[j]; ++j)
		inet_ntoa(*((struct in_addr *)h->h_addr_list[j]));
	if (j > 1) {
		DEBUG_MSG("wildcard domain\'s number of IP address(es): %d"
				" (this causes dnsmap to produce false positives)\n", j);
		return FALSE;
	}

	return TRUE;
}

