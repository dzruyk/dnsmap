CC=gcc
CFLAGS=-I. -Wall -ggdb
BINDIR=/usr/local/bin

dnsmap: dnsmap.c dnsmap.h
	$(CC) $(CFLAGS) -o dnsmap dnsmap.c
clean:
	rm -rf *~ *.o dnsmap

install: dnsmap
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 0755 dnsmap $(DESTDIR)$(BINDIR)
	install -m 0755 dnsmap-bulk.sh $(DESTDIR)$(BINDIR)/dnsmap-bulk

