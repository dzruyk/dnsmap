/*
* ** dnsmap - DNS Network Mapper by pagvac
* ** Copyright (C) 2010 gnucitizen.org
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
#include "dnsmap.h" // built-in subdomains list and define macros

// function prototypes
unsigned short int wildcarDetect(char *, char *);
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
char wordlistFilename[MAXSTRSIZE]={'\0'};

int delay = 0;

char results_fn[MAXSTRSIZE]={'\0'};
FILE *fp_out;

int filtered_ip_cnt = 0;
char *filterIPs[5][INET_ADDRSTRLEN]={{'\0'}},

void
parse_ip_filter(char *str)
{
	char *strP;
	int i;

	// filter out user-provided IP(s)
	for(filtered_ip_cnt = 1,i = 0; optind[i]!='\0'; ++i)
		if(optind[i]==',')
			++filtered_ip_cnt;

	DEBUG_MSG("%d IP(s) to filter found\nParsing ...\n", filtered_ip_cnt);

	if(filtered_ip_cnt <= 5) {
		printf(FILTERMSG);
		strP = strtok(optind, ",");
		for(i = 0; strP;) {
			if(strlen(strP) < INET_ADDRSTRLEN) {
				strncpy(filterIPs[i], strP, INET_ADDRSTRLEN);
				DEBUG_MSG("%s\n",filterIPs[i]);
				++i;
			}
			strP = strtok(NULL, " ,");
		}
	} else {
		printf(FILTIPINPUTERR);
		exit(1);
	} 
}

void
parse_args()
{
	char *name;
	int outfmt = OUT_STD;

	if(argc == 1) {
		printf("%s%s", USAGE, EXAMPLES);
		exit(1);
	}
	else if(argc % 2 == 1 && argc > 2) {
		printf("%s%s", USAGE, EXAMPLES);
		exit(1);
	}

	while (getopt(argc, argv, "w:r:c:d:i:")) {
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
		fp_out = fopen(results_fn, "a");
		if(!fp_out) {
			printf(CREATEFILEERR);
			exit(1);
		}
	}
	
	dnsname = argv[0];

	for(i = 0; dnsname[i]; ++i) // convert domain to lower case
		dnsname[i] = (tolower(dnsname[i]));
	DEBUG_MSG("domain: %s\n", dnsname);
	if(!isValidDomain(dnsname)) {
		printf("%s", DOMAINERR);
		exit(1);
	}
}

int main(int argc, char *argv[]) {

	unsigned short int i=0, j=0, k=0, l=0, found=0, ipCount=0, delay=10, intIPcount=0,
		wordlist=FALSE, txtResults=FALSE, csvResults=FALSE,
		delay=TRUE, filter=FALSE;
	unsigned long int start=0, end=0;
	char dom[MAXSTRSIZE]={'\0'}, csvResultsFilename[MAXSTRSIZE]={'\0'},
		
		ipstr[INET_ADDRSTRLEN]={'\0'}, wildcardIpStr[INET_ADDRSTRLEN]={'\0'},
		invalidTldIpstr[INET_ADDRSTRLEN]={'\0'};
	void *addr;
	char *ipver;

	struct hostent *h;
	// start of IPv6 stuff
	struct addrinfo hints, *res, *p;
	int status;
	char ipv6str[INET6_ADDRSTRLEN];
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6; // AF_INET or AF_INET6 to force version
	hints.ai_socktype = SOCK_STREAM;
	// end of IPv6 stuff

	FILE *fpWords,*fpCsvLogs,*fpTxtLogs;

	printf("%s", BANNER);

	// get the current time

	for(i=0;i<argc;++i) {
		if((strlen(argv[i]))>MAXSTRSIZE) {
			printf("%s",INPUTERR);
			exit(1);
		}
	}
	// end of simple input validation

	start=(int)time(NULL);

	DEBUG_MSG("start time: %d\n", (int)start);

	parse_args();

	// read subdomains from built-in list
	if(!wordlist) {
		// openDNS detection
		if(usesOpenDNS(invalidTldIpstr))
			printf("%s",OPENDNSMSG);

		// wildcard detection
		wildcarDetect(dnsname,wildcardIpStr);

		if(strcmp(invalidTldIpstr,wildcardIpStr))
			printf(WILDCARDWARN);
		printf(BUILTINMSG);
		if(delay>=1)
			printf(DELAYMSG);

		printf("%s", "\n");
		for(i=0;i<(sizeof(sub)/MAXSUBSIZE);++i) {
			//skipResolve=FALSE;
			strncpy(dom,sub[i],MAXSTRSIZE-strlen(dom)-1);
			strncat(dom,".",MAXSTRSIZE-strlen(dom)-1);//TEST
			strncat(dom,dnsname,MAXSTRSIZE-strlen(dom)-1);
			DEBUG_MSG("brute-forced domain: %s\n",dom);

			// ipv6 code modded from www.kame.net
			status = getaddrinfo(dom, NULL, &hints, &res);
			if ((status=getaddrinfo(dom, NULL, &hints, &res))==0) {
				printf("%s\n", dom);
				++found;
				if(txtResults)
					fprintf(fpTxtLogs, "%s\n", dom);
				if(csvResults)
					fprintf(fpCsvLogs, "%s", dom);
				for(p=res,k=0;p;p=p->ai_next,++k) {
					if (p->ai_family==AF_INET6) { // IPv6
						struct sockaddr_in6 *ipv6=(struct sockaddr_in6 *)p->ai_addr;
						addr = &(ipv6->sin6_addr);
						ipver = "IPv6";
					}
					// convert the IP to a string and print it:
					inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
					printf("%s address #%d: %s\n",ipver,k+1,ipv6str);
					++ipCount;
					if(txtResults)
						fprintf(fpTxtLogs,"%s address #%d: %s\n",ipver,k+1,ipv6str);
					if(csvResults)
						fprintf(fpCsvLogs,",%s", ipv6str);
				}
				printf("%s", "\n");
				if(txtResults)
					fprintf(fpTxtLogs,"\n");
				if(csvResults)
					fprintf(fpCsvLogs,"\n");
				freeaddrinfo(res); // free the linked list
			} // end of if conditional
			h=gethostbyname(dom);
			//sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[0])),"%s");
			//for(j=0;h->h_addr_list[j];++j) {
			//	sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[j])),"%s");
			//	if(isIPblacklisted(ipstr)) {
			//		skipResolve=TRUE;
			//		break;
			//	}
			//}
			//if(h && !skipResolve) {
			//if(h && !isIPblacklisted(ipstr)) {
			if(h && !isIPblacklisted(inet_ntoa(*((struct in_addr *)h->h_addr_list[0])))) {
				for(j=0;h->h_addr_list[j];++j) {
					sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[j])),"%s");
					for(k=0;k<filtered_ip_cnt;++k) {
						if(strcmp(filterIPs[k],ipstr)==0) { // filtered IP found
							// 1st IP of array - weird output formatting bug
							if(j!=0 && strcmp(wildcardIpStr,filterIPs[k])) {
								printf("\n");
								if(txtResults)
									fprintf(fpTxtLogs, "%s", "\n");
								if(csvResults)
									fprintf(fpCsvLogs, "%s", "\n");
							}
							DEBUG_MSG("%s found and ignored\n",filterIPs[k]);
							filter=TRUE;
							if(h->h_addr_list[j+1])
								++j;
							else
								break;
						}
					}
					// END OF TEST
					//if(strcmp(wildcardIpStr,ipstr) && strcmp(filterIpStr,ipstr)) {
					if(strcmp(wildcardIpStr,ipstr) && filter==FALSE) {
						if(j==0) {
							++found;
							printf("%s\n", dom);

							if(txtResults)
								fprintf(fpTxtLogs, "%s\n", dom);
							if(csvResults)
								fprintf(fpCsvLogs, "%s", dom);
						}
						printf("IP address #%d: %s\n", j+1,ipstr);
						++ipCount;

						if(isPrivateIP(ipstr)) {
						//if(isPrivateIP(inet_ntoa(*((struct in_addr *)h->h_addr_list[j])))) {
							printf("%s",INTIPWARN);
							++intIPcount;
						}
						if(!strcmp(ipstr,"127.0.0.1") && strcmp(wildcardIpStr,ipstr)) {
						//if(!strcmp(inet_ntoa(*((struct in_addr *)h->h_addr_list[j])),
							//"127.0.0.1"))
							printf("%s",SAMESITEXSSWARN);
						}
						if(txtResults) {
							//fprintf(fpCsvLogs,",%s",
							//	inet_ntoa(*((struct in_addr *)h->h_addr_list[j])));
							fprintf(fpTxtLogs,"IP address #%d: %s\n", j+1, ipstr);
							if(isPrivateIP(ipstr) && strcmp(wildcardIpStr,ipstr))
								fprintf(fpTxtLogs,"%s",INTIPWARN);
							if(!strcmp(ipstr,"127.0.0.1") && strcmp(wildcardIpStr,ipstr))
								fprintf(fpTxtLogs,"%s",SAMESITEXSSWARN);
						}
						if(csvResults && strcmp(wildcardIpStr,ipstr))
							fprintf(fpCsvLogs,",%s",ipstr);
					}
				}
				//if(strcmp(wildcardIpStr,ipstr) && strcmp(filterIpStr,ipstr)) {
				if(strcmp(wildcardIpStr,ipstr) && filter==FALSE) {
					printf("%s", "\n");
					if(txtResults)
						fprintf(fpTxtLogs,"%s","\n");
					if(csvResults)
						fprintf(fpCsvLogs,"%s","\n");
				}
				filter=FALSE;
			}
			// user wants delay between DNS requests?
			if(delay)
				dodelay(delay);
		}
		if(txtResults)
			fclose(fpTxtLogs);
		if(csvResults)
			fclose(fpCsvLogs);
	}

	// read subdomains from wordlist file
	else if(wordlist) {
		// openDNS detection
		if(usesOpenDNS(invalidTldIpstr))
			printf("%s",OPENDNSMSG);

		// wildcard detection
		wildcarDetect(dnsname,wildcardIpStr);
		if(strcmp(invalidTldIpstr,wildcardIpStr))
			printf(WILDCARDWARN);

		fpWords=fopen(wordlistFilename, "r");
		if(fpWords) {
			printf(EXTERNALMSG);
			if(delay>=1)
				printf(DELAYMSG);
			printf("%s","\n");

			while(!feof(fpWords)) {
				//strncpy(dom,"",MAXSTRSIZE-strlen(dom)-1);
				for(i=0;i<strlen(dom);++i)
					dom[i]='\0';
				fscanf(fpWords,"%100s",dom); // wordlist subdomain not allowed to be more than 100 chars
				DEBUG_MSG("lengh of dom: %d\n",strlen(dom));
				strncat(dom,".",MAXSTRSIZE-strlen(dom)-1);
				strncat(dom,dnsname,MAXSTRSIZE-strlen(dom)-1);

				DEBUG_MSG("brute-forced domain: %s\n",dom);
				// ipv6 code modded from www.kame.net
				status = getaddrinfo(dom, NULL, &hints, &res);
				if ((status=getaddrinfo(dom, NULL, &hints, &res))==0) {
					printf("%s\n", dom);
					++found;
					if(txtResults)
						fprintf(fpTxtLogs, "%s\n", dom);
					if(csvResults)
						fprintf(fpCsvLogs, "%s", dom);
					for(p=res,k=0;p;p=p->ai_next,++k) {
						void *addr;
						char *ipver;
						if (p->ai_family==AF_INET6) { // IPv6
							struct sockaddr_in6 *ipv6=(struct sockaddr_in6 *)p->ai_addr;
							addr = &(ipv6->sin6_addr);
							ipver = "IPv6";
						}
						// convert the IP to a string and print it:
						inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
						printf("%s address #%d: %s\n",ipver,k+1,ipv6str);
						++ipCount;
						if(txtResults)
							fprintf(fpTxtLogs,"%s address #%d: %s\n",ipver,k+1,ipv6str);
						if(csvResults)
							fprintf(fpCsvLogs,",%s", ipv6str);
					}
					printf("%s", "\n");
					if(txtResults)
						fprintf(fpTxtLogs,"\n");
					if(csvResults)
						fprintf(fpCsvLogs,"\n");

					freeaddrinfo(res); // free the linked list
					// ipv6 code modded from www.kame.net
				} // end of if conditional

				h=gethostbyname(dom);

				if(h && !isIPblacklisted(inet_ntoa(*((struct in_addr *)h->h_addr_list[0])))) {
					for(j=0;h->h_addr_list[j];++j) {
						sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[j])),"%s");
						//TEST
						for(k=0;k<filtered_ip_cnt;++k) {
							if(strcmp(filterIPs[k],ipstr)==0) { // filtered IP found
								// 1st IP of array - weird output formatting bug
								if(j!=0 && strcmp(wildcardIpStr,filterIPs[k])) {
									printf("\n");
									if(txtResults)
										fprintf(fpTxtLogs, "%s", "\n");
									if(csvResults)
										fprintf(fpCsvLogs, "%s", "\n");
								}
								DEBUG_MSG("%s found and ignored\n",filterIPs[k]);
								filter=TRUE;
								if(h->h_addr_list[j+1])
									++j;
								else
									break;
							}
						}
						// END OF TEST

						//if(strcmp(wildcardIpStr,ipstr) && strcmp(filterIpStr,ipstr)) {
						if(strcmp(wildcardIpStr,ipstr) && filter==FALSE) {
							if(j==0) {
								++found;
								printf("%s\n",dom);

								if(txtResults) {
									//fprintf(fpCsvLogs,"%s",dom);
									fprintf(fpTxtLogs,"%s\n",dom);
								}
								if(csvResults) {
									//fprintf(fpCsvLogs,"%s",dom);
									fprintf(fpCsvLogs,"%s",dom);
								}
							}
							printf("IP address #%d: %s\n",j+1,ipstr);
							++ipCount;

							if(isPrivateIP(ipstr) && strcmp(wildcardIpStr,ipstr)) {
								printf("%s",INTIPWARN);
								++intIPcount;
							}
							if(!strcmp(ipstr,"127.0.0.1") && strcmp(wildcardIpStr,ipstr))
								printf("%s",SAMESITEXSSWARN);
							if(txtResults && strcmp(wildcardIpStr,ipstr)) {
								fprintf(fpTxtLogs,"IP address #%d: %s\n",j+1,ipstr);
								if(isPrivateIP(ipstr))
									fprintf(fpTxtLogs,"%s",INTIPWARN);
								if(!strcmp(ipstr,"127.0.0.1"))
									fprintf(fpTxtLogs,"%s",SAMESITEXSSWARN);
							}
							if(csvResults && strcmp(wildcardIpStr,ipstr))
								fprintf(fpCsvLogs,",%s",ipstr);
						}
					}
					//if(strcmp(wildcardIpStr,ipstr) && strcmp(filterIpStr,ipstr)) {
					if(strcmp(wildcardIpStr,ipstr) && filter==FALSE) {
							printf("%s", "\n");
						if(txtResults)
							fprintf(fpTxtLogs,"%s","\n");
						if(csvResults)
							fprintf(fpCsvLogs,"%s","\n");
					}
					filter=FALSE;
				}
				// user wants delay between DNS requests?
				if(delay)
					dodelay(delay);
			} // end while() loop
			fclose(fpWords);
		}
		else {
			printf(OPENFILEERR);
			exit(1);
		}
		if(txtResults)
			fclose(fpTxtLogs);
		if(csvResults)
			fclose(fpCsvLogs);
	}

	printf(RESULTSMSG4);
	if(intIPcount>=1)
		printf(RESULTSMSG1);

	if(txtResults)
		printf(RESULTSMSG2);
	if(csvResults)
		printf(RESULTSMSG5);

	end=(int)time(NULL);
	printf(RESULTSMSG3);

	return 0;
}

// return true if domain wildcards are enabled
unsigned short int wildcarDetect(char *dom, char *ipstr) {
	char strTmp[30]={'\0'},s[MAXSTRSIZE]={'\0'};
	unsigned short int i=0,n=0,max=0;
	struct hostent *h;

	srand(time(NULL));
	max=rand()%20;
	// max should be between 10 and 20
	if(max<10)
		max=max+(10-max);

	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554

	for(i=0;i<max;++i) {
		n=rand()%10;
		sprintf(strTmp, "%d", n);
		if(i==0)
			strncpy(s,strTmp,MAXSTRSIZE-strlen(s)-1);
		else
			strncat(s,strTmp,MAXSTRSIZE-strlen(s)-1);
	}
	strncat(s,".",MAXSTRSIZE-strlen(s)-1);
	strncat(s, dom,MAXSTRSIZE-strlen(s)-1);
	DEBUG_MSG("random subdomain for wildcard testing: %s\n",s);

	// random subdomain resolves, thus wildcards are enabled
	h=gethostbyname(s); // replace with getaddrinfo() ?
	if(h) { /*
		for(i=0;h->h_addr_list[i];++i) {
		*/
		//sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[i])),"%s");
		sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[0])),"%s");
		DEBUG_MSG("wildcard domain\'s IP address: %s\n",ipstr);
		return TRUE;
	}
	else
		return FALSE;
}

// return number of delay delayed
unsigned short int dodelay(unsigned short int maxmillisecs) {
	unsigned short int n=0;

	srand(time(NULL));
	n=rand() % maxmillisecs;
	++n;
	maxmillisecs = n;
	DEBUG_MSG("sleeping %d ms ...\n",maxmillisecs);
	usleep(maxmillisecs*1000);

	return maxmillisecs;
}

// return true if IP addr is internal (RFC1918)
unsigned short int isPrivateIP(char *ip) {

	char classB[][8]={"172.16.","172.17.","172.18.","172.19.",
		"172.20.","172.21.","172.22.","172.23.","172.24.",
		"172.25.","172.26.","172.27.","172.28.","172.29.",
		"172.30.","172.31."};

	unsigned short int i=0,j=0;
	size_t len = strlen(ip);

	// shortest: 0.0.0.0 - 8 chars inc \0
	// longest: 255.255.255.255 - 16 chars inc \0
	if(len<8 || len>16)
		return 0;
	// ip addr must have three period signs
	for(i=0,j=0;i<len;++i) {
		if(ip[i]=='.')
			++j;
	}
	if(j!=3 || ip[0]=='.' || ip[len-1]=='.')
		return 0;

	// 10.0.0.0 - 10.255.255.255 (10/8 prefix)
	if(strncmp(ip,"10.",3)==0)
		return 1;

	// 192.168.0.0 - 192.168.255.255 (192.168/16 prefix)
	else if(strncmp(ip,"192.168.",8)==0)
		return 1;


	else {
		// 172.16.0.0 - 172.31.255.255  (172.16/12 prefix)
		for(i=0;i<sizeof(classB)/8;++i) {
			if(strncmp(ip,classB[i],7)==0)
				return 1;
		}
		return 0;
	}
}

// return true if domain is valid, false otherwise
unsigned short int isValidDomain(char *d) {

	unsigned int i=0, j=0;
	char *tld;
	size_t len;
	char strTmp[30]={'\0'},s[MAXSTRSIZE]={'\0'};
	unsigned short int n=0,max=0;

	struct hostent *h;

	if(strlen(d)<4) // smallest possible domain provided. e.g. a.pl
		return 0;
	if(!strstr(d,".")) // target domain must have at least one dot. e.g. target.va, branch.target.va
		return 0;
	tld=strstr(d,".");
	tld=tld+1;
	while(strstr(tld,".")){
		tld=strstr(tld,".");
		tld=tld+1;
	}
	DEBUG_MSG("tld\'s length: %d\n",strlen(tld));
	DEBUG_MSG("dom: %s tld: %s\n",d,tld);
	if((strlen(tld)<2) || (strlen(tld)>6)) // tld must be between 2-6 char. e.g. .museum, .uk
		return FALSE;

	// valid domain can only contain digits, letters, dot (.) and dash symbol (-)
	len = strlen(d);
	for(i=0;i<len;++i) {
		if (!(d[i] >= '0' && d[i] <= '9') &&
			!(d[i] >= 'a' && d[i] <= 'z') &&
			!(d[i] >= 'A' && d[i] <= 'Z') &&
			!(d[i] >= '-' && d[i] <= '.'))
			return 0;
	}

	srand(time(NULL));
	max=rand()%20;
	// max should be between 10 and 20
	if(max<10)
		max=max+(10-max);

	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554

	for(i=0;i<max;++i) {
		n=rand()%10;
		sprintf(strTmp, "%d", n);
		if(i==0)
			strncpy(s,strTmp,MAXSTRSIZE-strlen(s)-1);
		else
			strncat(s,strTmp,MAXSTRSIZE-strlen(s)-1);
	}
	strncat(s,".",MAXSTRSIZE-strlen(s)-1);
	strncat(s, d,MAXSTRSIZE-strlen(s)-1);
	DEBUG_MSG("random subdomain for wildcard testing: %s\n",s);

	// some domains like proboards.com return more than 1 IP address
	// when resolving random subdomains (wildcards are enabled)
	h=gethostbyname(s);
	if(h) {
		for(j=0;h->h_addr_list[j];++j)
			inet_ntoa(*((struct in_addr *)h->h_addr_list[j]));
		if(j>1) {
			DEBUG_MSG("wildcard domain\'s number of IP address(es): %d"
					" (this causes dnsmap to produce false positives)\n",j);
			return FALSE;
		}
	}

	return TRUE;
}

// return true if IP is blacklisted, false otherwise
unsigned short int isIPblacklisted(char *ip) {
	int i;
	// add you own blacklisted IP addresses here if dnsmap is producing false positives.
	// this could be caused by your ISP returning a captive portal search page when
	// when requesting invalid domains on your browser
	char ips[][INET_ADDRSTRLEN]={
					"81.200.64.50",
					"67.215.66.132",
					"1.2.3.4",
					"0.0.0.0"	// add your false positive IPs here
					};

	//for(i=0;ips[i];++i) {
	for(i=0;i<(sizeof(ips)/INET_ADDRSTRLEN);++i) {
		if(!strcmp(ips[i],ip))
			return TRUE;
	}

	return FALSE;
}


// return true if usage of public DNS server is detected
// Note: right now this function only detects openDNS, but might be
// updated in the future to detect other common public DNS servers
unsigned short int usesOpenDNS(char *ipstr) {
	char strTmp[30]={'\0'}, s[MAXSTRSIZE]={'\0'}, dummyLTD[4]={"xyz"}/*, ipstr[INET_ADDRSTRLEN]={'\0'}*/;
	char ips[][INET_ADDRSTRLEN]={"67.215.65.132"};
	unsigned short int i=0,j=0,n=0,max=0;
	struct hostent *h;

	srand(time(NULL));
	max=rand()%20;
	// max should be between 10 and 20
	if(max<10)
		max=max+(10-max);

	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554

	for(i=0;i<max;++i) {
		n=rand()%10;
		sprintf(strTmp, "%d", n);
		if(i==0)
			strncpy(s,strTmp,MAXSTRSIZE-strlen(s)-1);
		else
			strncat(s,strTmp,MAXSTRSIZE-strlen(s)-1);
	}
	strncat(s,".",MAXSTRSIZE-strlen(s)-1);
	strncat(s, dummyLTD,MAXSTRSIZE-strlen(s)-1);
	DEBUG_MSG("random domain for public DNS testing: %s\n",s);

	// random invalid domain resolves, thus public DNS in use
	h=gethostbyname(s);
	if(h) {
		for(i=0;h->h_addr_list[i];++i) {
			sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[i])),"%s");
			DEBUG_MSG("public DNS server\'s default IP address #%d: %s\n",i+1,ipstr);
			for(j=0;i<(sizeof(ips)/INET_ADDRSTRLEN);++j) {
					if(!strcmp(ips[i],ipstr))
						return TRUE;
			}
		}
		return TRUE;
	}
	else
		return FALSE;
}
