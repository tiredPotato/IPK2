#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#include<pcap.h>


struct Arguments {
    char interface = [];
    int port = 0;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp = false;
    int num = 0;
};


//./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}

Arguments argParse(int argc, char *argv[]) {
    Arguments args;
    int opt;

    while((opt = getopt(argc, argv, ":tu:pn")) != -1) {
        switch (opt)
        {
        case 'i':
            /* code */
            break;

        case 'p':
            if (optarg)
            args.port = 
        
        default:
            break;
        }
    }
}