#
# Makefile pre 2. projekt z IPK
# Adriana Jurkechová, FIT VUT Brno
# Dátum: 25.4.2021
#

all: ipk-sniffer

ipk-sniffer:
	g++ -o ipk-sniffer ipk-sniffer.cpp -lpcap

clean:
	rm ipk-sniffer
