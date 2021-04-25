#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<getopt.h>
#include<time.h>
#include<signal.h>

#include<pcap/pcap.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/icmp6.h>


/**
 * @struct Štruktúra všetkých možných argumentov na vstupe 
 */
struct Arguments {
    const char *interface;
    const char *port = NULL;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp = false;
    int num = 1;
};


/**
 * @brief Funkcia vypisujúca časovú počiatku vo formáte YY-MM-DDTHH:MM:SS.000+00:000
 * @param h Štruktúra paketovej hlavičky
*/
void printTimeStamp(const struct pcap_pkthdr *h) {

    char buff[28];

    struct tm *gm = gmtime(&h->ts.tv_sec);

    ssize_t timestamp = (ssize_t)strftime(buff, sizeof(buff), "%FT%T", gm);
    int formatting = snprintf(buff+timestamp, sizeof(buff)-(size_t)timestamp, ".%03d", h->ts.tv_usec/1000);
    printf("\n%s", buff);
    ssize_t hour = (ssize_t)strftime(buff, sizeof(buff), "%z", gm);
    if (hour > 1) {
        char minute[] = { buff[hour-2], buff[hour-1], '\0'};
        sprintf(buff + hour - 2, ":%s", minute);
    }
    printf("%s ", buff);
}

/**
 * @brief Funkcia na vypísanie celého paketu
 * @param h Štruktúra paketovej hlavičky
 * @param bytes Pole obsahujúce dáta paketu
*/
void printPacket(const struct pcap_pkthdr *h, const u_char *bytes) {
    int len = h->len;
    for (int i = 0; i < h->caplen; i++) {
        if(i%16 == 0 && i != 0) {
            for (int j =i-16; j<i; j++)
            {
                if(bytes[j]>= 32 && bytes[j]<=128)
                    printf("%c", (u_char)bytes[j]);
                else printf(".");
            }
        }
        if(i%16 == 0) {
            printf("\n0x%04x: ", i);
        }
        printf("%02x ", bytes[i]);
        if(i == len-1) {
            for(int j = 0; j<15-i%16; j++) {
                printf("   ");
            }
            for (int j = i-i%16; j <= i; j++)
            {
                if(bytes[j]>= 32 && bytes[j]<=128)
                    printf("%c", (u_char)bytes[j]);
                else printf(".");
            }
            
        }
    }
}


/**
 * @brief Funkcia vypisujúca dáta z hlavičky TCP paketu
 * @param h Štruktúra paketovej hlavičky
 * @param ipheader Štruktúra hlavičky protokolu
 * @param bytes Pole obsahujúce dáta paketu 
*/
void printTCP(const struct pcap_pkthdr *h, struct iphdr *ipheader, const u_char *bytes) {

    printTimeStamp(h);

    struct sockaddr_in source;
    struct sockaddr_in destination;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipheader->saddr;
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = ipheader->daddr;

    struct tcphdr *tcpheader=(struct tcphdr*)(bytes + sizeof(struct iphdr) + sizeof(struct ethhdr));

    printf("%s : ", inet_ntoa(source.sin_addr));
    printf("%u > ", ntohs(tcpheader->source));
    printf("%s : ", inet_ntoa(destination.sin_addr));
    printf("%u, ", ntohs(tcpheader->dest));
    printf("length %d bytes\n", h->len);
    printPacket(h, bytes);
    
}


/**
 * @brief Funkcia vypisujúca dáta z hlavičky UDP paketu
 * @param h Štruktúra paketovej hlavičky
 * @param ipheader Štruktúra hlavičky protokolu
 * @param bytes Pole obsahujúce dáta paketu 
*/
void printUDP(const struct pcap_pkthdr *h, struct iphdr *ipheader, const u_char *bytes) {

    printTimeStamp(h);

    struct sockaddr_in source;
    struct sockaddr_in destination;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipheader->saddr;
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = ipheader->daddr;

    struct udphdr *udpheader=(struct udphdr*)(bytes + sizeof(struct iphdr) + sizeof(struct ethhdr));

    printf("%s : ", inet_ntoa(source.sin_addr));
    printf("%u > ", ntohs(udpheader->source));
    printf("%s : ", inet_ntoa(destination.sin_addr));
    printf("%u, ", ntohs(udpheader->dest));
    printf("length %d bytes\n", h->len);
    printPacket(h, bytes);
    
}


/**
 * @brief Funkcia vypisujúca dáta z hlavičky ICMPv4 paketu
 * @param h Štruktúra paketovej hlavičky
 * @param ipheader Štruktúra hlavičky protokolu
 * @param bytes Pole obsahujúce dáta paketu 
*/
void printICMPv4(const struct pcap_pkthdr *h, struct iphdr *ipheader, const u_char *bytes) {

    printTimeStamp(h);

    struct sockaddr_in source;
    struct sockaddr_in destination;
    

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipheader->saddr;
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = ipheader->daddr;

    printf("%s ", inet_ntoa(source.sin_addr));
    printf("> %s, ", inet_ntoa(destination.sin_addr));
    printf("length %d bytes\n", h->len);
    printPacket(h, bytes);
}


/**
 * @brief Funkcia vypisujúca dáta z hlavičky ICMPv6 paketu
 * @param h Štruktúra paketovej hlavičky
 * @param ipheader Štruktúra hlavičky protokolu
 * @param bytes Pole obsahujúce dáta paketu 
*/
void printICMPv6(const struct pcap_pkthdr *h, struct iphdr *ipheader, const u_char *bytes) {

    printTimeStamp(h);

    char source[INET6_ADDRSTRLEN];
    char dest[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, bytes+22, source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, bytes+38, dest, INET6_ADDRSTRLEN);
    printf("%s > ", source);
    printf("%s, ", dest);
   // printf("%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x > ", bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31], bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37]);
   // printf("%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x, ", bytes[38], bytes[39], bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53]);
    printf("length %d bytes\n", h->len);

    printPacket(h, bytes);

}


/**
 * @brief Funkcia vypisujúca dáta z hlavičky ARP rámca
 * @param h Štruktúra paketovej hlavičky
 * @param header Štruktúra ethernetovej hlavičky
 * @param bytes Pole obsahujúce dáta paketu 
*/
void printARP(const struct pcap_pkthdr *h, struct ether_header *header, const u_char *bytes) {

    printTimeStamp(h);

    printf("%.2x-%.2x-%.2x-%.2x-%.2x-%.2x > ", header->ether_shost[0], header->ether_shost[1], header->ether_shost[2], header->ether_shost[3], header->ether_shost[4], header->ether_shost[5]);
    printf("%.2x-%.2x-%.2x-%.2x-%.2x-%.2x, ", header->ether_dhost[0], header->ether_dhost[1], header->ether_dhost[2], header->ether_dhost[3], header->ether_dhost[4], header->ether_dhost[5]);
    printf("length %d bytes\n", h->len);
    printPacket(h, bytes);
}


/**
 * @brief Funkcia spracovavajúca odchytené pakety
 * @param user 
 * @param h Štruktúra paketovej hlavičky
 * @param bytes Pole obsahujúce dáta paketu 
*/
void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    struct iphdr *ipheader = (struct iphdr*)(bytes + sizeof(struct ether_header));
    switch (ipheader->protocol)
    {
    case IPPROTO_ICMP: //ICMPv4 PROTOCOL
        printICMPv4(h, ipheader, bytes);
        break;
    case IPPROTO_TCP: //TCP PROTOCOL
        printTCP(h, ipheader, bytes);
        break;
    case IPPROTO_UDP: //UDP PROTOCOL
        printUDP(h, ipheader, bytes);
        break;
    case IPPROTO_ICMPV6: //ICMPv6 PROTOCOL
        printICMPv6(h, ipheader, bytes);
        break;
    default:
        break;
    }


    struct ether_header *header = (ether_header*) bytes;

    switch(ntohs(header->ether_type)) {
        case ETHERTYPE_ARP: //ARP
            printARP(h, header, bytes);
            break;
        case ETHERTYPE_IPV6: //IPV6
            break;
        case ETHERTYPE_IP: //IPV4
            break;
        default: 
            break;
    }

    printf("\n");
};


//./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}


/**
 * @brief Funkcia spracovavajúca zadané argumenty pomocou funkcie getopts_long()
 * @param argc Počet argumentov
 * @param argv Pole argumentov
 * @return Vracia štruktúru Arguments
*/
Arguments argParse(int argc, char *argv[]) {

    Arguments args;
    pcap_if_t *alldevsp, *device;
    char errbuf[100];
    static struct option long_option[] = 
    {
        {"interface", optional_argument, NULL, 'i'},
        {"tcp", no_argument, NULL, 't'},
        {"udp", no_argument, NULL, 'u'},
        {"arp", no_argument, NULL, 'a'},
        {"icmp", no_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
    };

    int ch;
    while((ch = getopt_long(argc, argv, ":i:p:tuhn:", long_option, NULL)) != -1) {
        switch (ch)
        {
        case 'i':
            args.interface = optarg;
            break;
        case 'p':
            args.port = optarg;
            break;
        case 't':
            args.tcp = true;
            break;
        case 'u':
            args.udp = true;
            break;
        case 'n':
            args.num = atoi(optarg);
            break;
        case 'a':
            args.arp = true;
            break;
        case 'c':
            args.icmp = true;
            break;
        case 'h':
            printf("Volanie programu:\n./ipk-sniffer [-i rozhranie | --interface rozhranie] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\nkde:\n");
            printf("-i rozhranie: je práve jedno rozhranie, na ktorom sa bude počúvať\n");
            printf("-p port: filtrovanie paketov na danom rozhraní podľa portu. Bez zadania sa uvažujú všetky porty\n");
            printf("-t alebo --tcp: filtrovanie iba TCP paketov\n");
            printf("-u alebo --udp: filtrovanie iba UDP paketov\n");
            printf("--icmp: filtrovanie iba ICMPv4 a ICMPv6 paketov\n");
            printf("--arp: filtrovanie iba ARP rámcov\n");
            printf("-n num: počet paketov, ktoré sa majú zobraziť, implicitne 1 paket\n");
            exit(0);
        case ':':
            if (pcap_findalldevs(&alldevsp, errbuf)) {
                printf("Error finding devices: %s\n", errbuf);
                exit(1);
            }
            for(device = alldevsp; device != NULL; device = device->next) {
                printf("%s\n", device->name);
                exit(0);
            }
        default:
            break;
        }
    }

    return args;
}



/**
 * @brief Funkcia vytvárajúca string na filtrovanie podľa zadaných argumentov
 * @param arguments Štruktúra argumentov
 * @param filter Pole charov
 * @return Vracia pole charov, resp. filter, ktorý sa použije pri filtrovaní paketov
*/
char *filter(Arguments arguments, char *filter) {
    if (arguments.port != NULL) {
        if (arguments.tcp) {
            strcpy(filter, "tcp port ");
            strcat(filter, arguments.port);
            if (arguments.udp) {
                strcat(filter, " or udp port ");
                strcat(filter, arguments.port);
                if (arguments.icmp) {
                    strcat(filter, " or icmp or icmp6");
                    if (arguments.arp) {
                        strcat(filter, " or arp");
                    }
                }
            } else if(arguments.icmp) {
                strcat(filter, " or icmp or icmp6");
                if (arguments.arp) {
                    strcat(filter, " or arp");
                }
            } else if(arguments.arp) {
                strcat(filter, " or arp");
            }
        } else if (arguments.udp) {
            strcpy(filter, "udp port ");
            strcat(filter, arguments.port);
            if (arguments.icmp) {
                strcat(filter, " or icmp or icmp6");
                if (arguments.arp) {
                    strcat(filter, " or arp");
                }
            } else if (arguments.arp) {
                strcat(filter, " or arp");
            }
        } else if (arguments.icmp) {
            stpcpy(filter, "icmp or icmp6");
            if (arguments.arp) {
                strcat(filter, " or arp");
            }
        } else if (arguments.arp) {
            strcpy(filter, "arp");
        } else {
            strcpy(filter, "tcp port ");
            strcat(filter, arguments.port);
            strcat(filter, " or udp port ");
            strcat(filter, arguments.port);
            strcat(filter, " or icmp or icmp6 or arp");
        }
    }
    else {
        if (arguments.tcp) {
            strcpy(filter, "tcp");
            if (arguments.udp) {
                strcat(filter, " or udp");
                if (arguments.icmp) {
                    strcat(filter, " or icmp or icmp6");
                    if (arguments.arp) {
                        strcat(filter, " or arp");
                    }
                }
            } else if (arguments.icmp) {
                strcat(filter, " or icmp or icmp6");
                if (arguments.arp) {
                    strcat(filter, " or arp");
                }
            } else if (arguments.arp) {
                strcat(filter, " or arp");
            }
        } else if (arguments.udp) {
            strcpy(filter, "udp");
            if (arguments.icmp) {
                strcat(filter, " or icmp or icmp6");
                if (arguments.arp) {
                    strcat(filter, " or arp");
                }
            } else if (arguments.arp) {
                strcat(filter, " or arp");
            }
        } else if (arguments.icmp) {
            strcpy(filter, "icmp or icmp6");
            if (arguments.arp) {
                strcat(filter, " or arp");
            }
        } else if (arguments.arp) {
            strcpy(filter, "arp");
        } else {
            strcpy(filter, "tcp or udp or icmp or icmp6 or arp");
        }
    }
    return filter;
}


void  INThandler(int s)
{
    signal(s, SIG_IGN);
    exit(0);
    getchar();
}


int main(int argc, char *argv[]){

    signal(SIGINT, INThandler);

    Arguments arguments = argParse(argc, argv);

    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;

    
    auto interface = pcap_open_live(arguments.interface, BUFSIZ, 1, 20, errbuf);
    //auto interface = pcap_open_offline(arguments.interface, errbuf);
    if (interface == NULL) {
        printf("%s\n", errbuf);
        return 1;
    }

    if (pcap_datalink(interface) != DLT_EN10MB) {
        fprintf(stderr, "Program podporuje iba Ethernet.\n");
        return 1;
    }

    char *filt;
    char *str = filter(arguments, filt);

    if(pcap_compile(interface, &fp, str, 1, PCAP_NETMASK_UNKNOWN));

    if (pcap_setfilter(interface, &fp) < 0) {
        fprintf(stderr, "Chyba pri nastavení filtra.\n");
        return 1;
    }


    if (pcap_loop(interface, arguments.num, handle_packet, NULL) < 0) {
        fprintf(stderr, "Nastala chyba pri odchtávaní paketu.\n");
        return 1;
    }

    return 0;
}