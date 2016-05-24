#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#define clean_errno() (errno == 0 ? "None" : strerror(errno))
#define log_err(M, ...)                                                        \
        fprintf(stderr, "[ERROR] (%s:%d: errno: %s) " M "\n", __FILE__,        \
                __LINE__, clean_errno(), ##__VA_ARGS__)
#define check(A, M, ...)                                                       \
        if (!(A)) {                                                            \
                log_err(M, ##__VA_ARGS__);                                     \
                errno = 0;                                                     \
                goto error;                                                    \
        }
#define log_debug(format, ...) do {                     \
        if (verbose)                                    \
                fprintf(stderr, format, ##__VA_ARGS__); \
        } while(0)

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128
#define DHCP_TIMEOUT 5

#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY 2

#define DHCP_HARDWARE_TYPE_10_EHTHERNET 1


// http://www.iana.org/assignments/bootp-dhcp-parameters/
// DHCP Message Types
#define DHCP_MESSAGE_TYPE_DISCOVER 1
#define DHCP_MESSAGE_TYPE_OFFER 2
#define DHCP_MESSAGE_TYPE_REQUEST 3
#define DHCP_MESSAGE_TYPE_DECLINE 4
#define DHCP_MESSAGE_TYPE_PACK 5
#define DHCP_MESSAGE_TYPE_PNACK 6
#define DHCP_MESSAGE_TYPE_RELEASE 7
#define DHCP_MESSAGE_TYPE_INFORM 8
// DHCP Options
#define DHCP_OPTION_PAD 0
#define DHCP_OPTION_REQ_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER 3
#define DHCP_OPTION_DNS 6
#define DHCP_OPTION_DOMAIN_NAME 15
#define DHCP_OPTION_BROADCAST_ADDRESS 28
#define DHCP_OPTION_REQ_IP 50
#define DHCP_OPTION_LEASE_TIME 51
#define DHCP_OPTION_DHCP 53
#define DHCP_OPTION_SERVER_ID 54
#define DHCP_OPTION_PARAMETER_REQ_LIST 55
#define DHCP_OPTION_MSG 56
#define DHCP_OPTION_RENEWAL_TIME 58
#define DHCP_OPTION_REBINDING_TIME 59
#define DHCP_OPTION_END 255

#define DHCP_OPTIONS_MAX_LEN 256

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_MAGIC_COOKIE 0x63825363

static int verbose = 0;

struct dhcphdr {
        uint8_t opcode;
        uint8_t htype;
        uint8_t hlen;
        uint8_t hops;
        uint32_t xid;
        uint16_t secs;
        uint16_t flags;
        in_addr_t ciaddr;
        in_addr_t yiaddr;
        in_addr_t siaddr;
        in_addr_t giaddr;
        uint8_t chaddr[DHCP_CHADDR_LEN];
        char sname[DHCP_SNAME_LEN];
        char file[DHCP_FILE_LEN];
        uint32_t magic_cookie;
        uint8_t options[0];
};

struct packet {
        struct ether_header* ethernet_header;
        struct ip* ip_header;
        struct udphdr* udp_header;
        struct dhcphdr* dhcp_header;
        size_t len;
        char frame[ETH_FRAME_LEN];
};

static ssize_t
get_mac_address(char* dev_name, uint8_t* mac)
{
        struct ifreq ifr;
        int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        check(sd != -1, "socket() failed");

        strcpy(ifr.ifr_name, dev_name);
        ssize_t rc = ioctl(sd, SIOCGIFHWADDR, &ifr);
        close(sd);
        check(rc == 0, "ioctl(SIOCGIFHWADDR) failed");

        memcpy(mac, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
        return 0;
error:
        return -1;
}

static unsigned short
in_cksum(uint16_t* addr, size_t len)
{
        register int sum = 0;
        uint16_t answer = 0;
        register uint16_t* w = addr;
        register int nleft = len;
        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }
        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(char*)(&answer) = *(char*)w;
                sum += answer;
        }
        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
        sum += (sum >> 16);                 /* add carry */
        answer = ~sum;                      /* truncate to 16 bits */
        return (answer);
}

static void
packet_init(struct packet* pkt)
{
        memset(pkt, 0, sizeof(struct packet));
        pkt->ethernet_header = (struct ether_header*)pkt->frame;
        pkt->ip_header = (struct ip*)(pkt->frame + sizeof(struct ether_header));
        pkt->udp_header = (struct udphdr*)(((uint8_t*)pkt->ip_header) + sizeof(struct ip));
        pkt->dhcp_header = (struct dhcphdr*)(((uint8_t*)pkt->udp_header) + sizeof(struct udphdr));
        pkt->len = 0;
}

static ssize_t
packet_verify(struct packet* pkt)
{
        if ((htons(pkt->ethernet_header->ether_type) == ETHERTYPE_IP)
             && (pkt->ip_header->ip_p == IPPROTO_UDP)
             && (ntohs(pkt->udp_header->uh_sport) == DHCP_SERVER_PORT)
             && (pkt->dhcp_header->opcode == DHCP_MESSAGE_TYPE_OFFER)) {
                size_t cksum_orig = pkt->ip_header->ip_sum;
                pkt->ip_header->ip_sum = 0;
                size_t cksum_calc = in_cksum((unsigned short*)pkt->ip_header,
                                             sizeof(struct ip));
                pkt->ip_header->ip_sum = cksum_orig;
                if (cksum_orig == cksum_calc)
                        return 0;
        }
        return -1;
}

static ssize_t
packet_send(char* dev, const int sock, struct packet* pkt)
{
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

        ssize_t rc;
        rc = ioctl(sock, SIOCGIFINDEX, &ifr);
        check(rc != -1, "ioctl(SIOCGIFINDEX) failed");

        struct sockaddr_ll dst_addr;
        memset(&dst_addr, 0, sizeof(dst_addr));
        dst_addr.sll_ifindex = ifr.ifr_ifindex;
        dst_addr.sll_halen = ETHER_ADDR_LEN;
        memset(dst_addr.sll_addr, -1, ETHER_ADDR_LEN);

        rc = sendto(sock, pkt->frame, pkt->len, 0,
                    (struct sockaddr*)&dst_addr, sizeof(dst_addr));
        check(rc != -1, "sendto() failed");

        return 0;
error:
        return rc;
}

static ssize_t
packet_recv(const int sock, struct packet* pkt, const int timeout)
{
        struct sockaddr_storage src_addr;
        memset(&src_addr, 0, sizeof(src_addr));
        socklen_t src_addr_len = sizeof(src_addr);
        ssize_t rc;

        time_t timer_start = time(0);
        do {
                rc = recvfrom(sock, pkt->frame, pkt->len, 0,
                              (struct sockaddr*)&src_addr, &src_addr_len);
                check(rc != -1, "recvfrom() failed");
                if (rc == (ssize_t)pkt->len)
                        continue;
                if (time(0) > timer_start + timeout) {
                        printf("Timeout.\n");
                        exit(EXIT_FAILURE);
                }
        } while (packet_verify(pkt) != 0);

        return 0;
error:
        return -1;
}

static void
ether_setup(struct ether_header* eframe, uint8_t* mac, size_t* len)
{
        memcpy(eframe->ether_shost, mac, ETHER_ADDR_LEN);
        memset(eframe->ether_dhost, -1, ETHER_ADDR_LEN);
        eframe->ether_type = htons(ETHERTYPE_IP);

        *len += sizeof(struct ether_header);
}

static void
ip_setup(struct ip* ip_header, size_t* len)
{
        *len += sizeof(struct ip);

        ip_header->ip_hl = 5;
        ip_header->ip_v = IPVERSION;
        ip_header->ip_tos = 0x10;
        ip_header->ip_len = htons(*len);
        ip_header->ip_id = htonl(0xffff);
        ip_header->ip_off = 0;
        ip_header->ip_ttl = 16;
        ip_header->ip_p = IPPROTO_UDP;
        ip_header->ip_sum = 0;
        ip_header->ip_src.s_addr = 0;
        ip_header->ip_dst.s_addr = 0xffffffff;
        ip_header->ip_sum = in_cksum((unsigned short*)ip_header, sizeof(struct ip));
}

static void
udp_setup(struct udphdr* udp_header, size_t* len)
{
        *len += sizeof(struct udphdr);

        udp_header->uh_sport = htons(DHCP_CLIENT_PORT);
        udp_header->uh_dport = htons(DHCP_SERVER_PORT);
        udp_header->uh_ulen = htons(*len);
        udp_header->uh_sum = 0;
}

static void
dhcp_setup(struct dhcphdr* dhcp, uint8_t* mac, size_t* len)
{
        *len += sizeof(struct dhcphdr);

        dhcp->opcode = DHCP_BOOTREQUEST;
        dhcp->htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
        dhcp->hlen = ETHER_ADDR_LEN;
        memcpy(dhcp->chaddr, mac, ETHER_ADDR_LEN);
        dhcp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);
}

static size_t
dhcp_option_set(uint8_t* options, uint8_t code, uint8_t* data, size_t len)
{
        options[0] = code;
        options[1] = len;
        memcpy(&options[2], data, len);

        return len + (sizeof(uint8_t) * 2);
}

inline static void
addr_print(char* msg, uint8_t* pos, size_t count)
{
        printf("%s", msg);
        while (count--) {
                printf(" %u.%u.%u.%u", pos[0],
                       pos[1], pos[2], pos[3]);
        }
        printf("\n");

}

inline static void
dhcp_type_print(uint8_t* msg_type_code)
{
        printf("Message-Type");
        switch (*msg_type_code) {
        case DHCP_MESSAGE_TYPE_OFFER:
                printf(" OFFER");
                break;
        case DHCP_MESSAGE_TYPE_PACK:
                printf(" ACK");
                break;
        case DHCP_MESSAGE_TYPE_PNACK:
                printf(" NACK");
                break;
        default:
                printf(" UNKNOWN");
        }
        printf("\n");
}

static void
dhcp_print(struct dhcphdr* dhcp)
{
        if (dhcp->chaddr) {
                struct ether_addr ether;
                memcpy(ether.ether_addr_octet, dhcp->chaddr, ETHER_ADDR_LEN);
                printf("Your-MAC %s\n", ether_ntoa(&ether));
        }

        if (dhcp->yiaddr) {
                struct in_addr ip;
                ip.s_addr = dhcp->yiaddr;
                printf("Your-IP %s\n", inet_ntoa(ip));
        }

        size_t len = 0;
        size_t op_len = 0;
        uint8_t* cur_pos = (uint8_t*)&dhcp->options;
        uint8_t code;
        while (len <= DHCP_OPTIONS_MAX_LEN) {
                code = *cur_pos++; len++;
                op_len = *cur_pos++; len++;
                if (code == DHCP_OPTION_PAD) {
                        continue;
                } else if (code == DHCP_OPTION_END) {
                        break;
                } else if (code == DHCP_OPTION_DHCP
                           && op_len == 1) {
                        dhcp_type_print(cur_pos);
                } else if (code == DHCP_OPTION_REQ_SUBNET_MASK
                           && op_len == 4) {
                        addr_print("Subnet-Mask", cur_pos, 1);
                } else if (code == DHCP_OPTION_ROUTER
                           && op_len >= 4 && op_len % 4 == 0) {
                        addr_print("Default-Gateways", cur_pos, op_len / 4);
                } else if (code == DHCP_OPTION_DNS
                           && op_len >= 4 && op_len % 4 == 0) {
                        addr_print("Domain-Name-Servers", cur_pos, op_len / 4);
                } else if (code == DHCP_OPTION_DOMAIN_NAME
                           && op_len > 0) {
                        printf("Domain-Name %.*s\n",
                               (int)op_len, cur_pos);
                } else if (code == DHCP_OPTION_BROADCAST_ADDRESS
                           && op_len == 4) {
                         addr_print("Broadcast-Address", cur_pos, 1);
                } else if (code == DHCP_OPTION_SERVER_ID
                           && op_len == 4) {
                        addr_print("Server-ID", cur_pos, 1);
                } else if (code == DHCP_OPTION_LEASE_TIME
                           && op_len == 4) {
                        printf("Lease-Time %d\n",
                               htonl(*(uint32_t*)cur_pos));
                } else if (code == DHCP_OPTION_MSG
                           && op_len > 0) {
                        printf("Server-Message \"%.*s\"\n",
                               (int)op_len, cur_pos);
                } else if (code == DHCP_OPTION_RENEWAL_TIME
                           && op_len == 4) {
                         printf("Renewal-Time %d\n",
                               htonl(*(uint32_t*)cur_pos));
                } else if (code == DHCP_OPTION_REBINDING_TIME
                           && op_len == 4) {
                         printf("Rebinding-Time %d\n",
                               htonl(*(uint32_t*)cur_pos));
                } else {
                        log_debug("Undefined-code %d\n", code);
                }
                cur_pos += op_len;
                len += op_len;
        }
}

static size_t
dhcp_options_setup(struct dhcphdr* dhcp, uint8_t req_type, in_addr_t req_ip)
{
        size_t len = 0;
        uint8_t option = req_type;
        len += dhcp_option_set(&dhcp->options[len], DHCP_OPTION_DHCP, &option,
                               sizeof(option));

        len += dhcp_option_set(&dhcp->options[len], DHCP_OPTION_REQ_IP,
                               (uint8_t*)&req_ip, sizeof(req_ip));

        uint8_t req_params[] = { DHCP_OPTION_REQ_SUBNET_MASK,
                                 DHCP_OPTION_ROUTER,
                                 DHCP_OPTION_DNS,
                                 DHCP_OPTION_DOMAIN_NAME };

        len += dhcp_option_set(&dhcp->options[len], DHCP_OPTION_PARAMETER_REQ_LIST,
                               req_params, sizeof(req_params));

        option = 0;
        len += dhcp_option_set(&dhcp->options[len], DHCP_OPTION_END, &option,
                               sizeof(option));

        return len;
}

static void
packet_setup(struct packet* pkt, uint8_t* mac, uint8_t req_type,
             in_addr_t req_ip)
{
        pkt->len = dhcp_options_setup(pkt->dhcp_header, req_type, req_ip);
        dhcp_setup(pkt->dhcp_header, mac, &pkt->len);
        udp_setup(pkt->udp_header, &pkt->len);
        ip_setup(pkt->ip_header, &pkt->len);
        ether_setup(pkt->ethernet_header, mac, &pkt->len);
}

inline static void
usage_print(char* exec_name)
{
        printf("Usage: %s -i <interface> [-h] [-v] [-d] [-r <ip>] [-q <ip>] [-m <MAC>] [-t <sec>]\n", exec_name);
}

inline static void
help_print(char* exec_name)
{
        usage_print(exec_name);
        printf("\n\t-h --help\t\t\tThis help message\n"
               "\t-v --verbose\t\t\tPrint debugging info to stderr\n"
               "\t-i --interface <interface>\tInterface name\n"
               "\t-d --discover\t\t\tDiscover DHCP Server\n"
               "\t-r --request <ip>\t\tRequest IP lease\n"
               "\t-q --release <ip>\t\tRelease IP lease\n"
               "\t-m --mac <MAC>\t\t\tMAC address\n"
               "\t-t --timeout <sec>\t\tTimeout (default 5 sec.)\n\n");
}

int
main(int argc, char* argv[])
{
        char* dev = NULL;
        char* optmac = NULL;
        uint8_t dhcp_action = DHCP_MESSAGE_TYPE_DISCOVER;
        struct in_addr ip;
        memset(&ip, 0, sizeof(ip));
        int opt;
        int timeout = DHCP_TIMEOUT;

        static struct option long_options[] = {
                { "help", no_argument, 0, 'h' },
                { "verbose", no_argument, 0, 'v' },
                { "interface", required_argument, 0, 'i' },
                { "discover", no_argument, 0, 'd' },
                { "request", required_argument, 0, 'r' },
                { "release", required_argument, 0,'q' },
                { "mac", required_argument, 0,'m' },
                { "timeout", required_argument, 0,'t' },
                { 0, 0, 0, 0 }
        };

        int long_index = 0;
        while ((opt = getopt_long(argc, argv, "hvi:dr:q:m:t:",
                   long_options, &long_index )) != -1) {
                switch (opt) {
                case 'h':
                        help_print(argv[0]);
                        exit(EXIT_SUCCESS);
                case 'v':
                        verbose = 1; 
                        break;
                case 'i':
                        dev = optarg;
                        break;
                case 'd':
                        dhcp_action = DHCP_MESSAGE_TYPE_DISCOVER;
                        ip.s_addr = 0;
                        break;
                case 'r':
                        dhcp_action = DHCP_MESSAGE_TYPE_REQUEST;
                        inet_aton(optarg, &ip);
                        break;
                case 'q':
                        dhcp_action = DHCP_MESSAGE_TYPE_RELEASE;
                        inet_aton(optarg, &ip);
                        break;
                case 'm':
                        optmac = optarg;
                        break;
                case 't':
                        timeout = (atoi(optarg));
                        break;
                default:
                        usage_print(argv[0]);
                        exit(EXIT_FAILURE);
                }
        }

        if (!dev) {
                usage_print(argv[0]);
                exit(EXIT_FAILURE);
        }

        uint8_t mac[ETHER_ADDR_LEN];
        ssize_t rc;
        if (!optmac){
                rc = get_mac_address(dev, mac);
                check(rc != -1, "get_mac_address() failed");
        } else {
                // dirty
                int optmac_ok = sscanf(optmac, "%2x:%2x:%2x:%2x:%2x:%2x", mac, mac+1, mac+2, mac+3, mac+4, mac+5);
                check(optmac_ok == 6, "bad MAC address provided");
        }

        int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        check(sd != -1, "socket() failed");

        struct packet pkt_local;
        packet_init(&pkt_local);
        packet_setup(&pkt_local, mac, dhcp_action, ip.s_addr);

        struct packet pkt_remote;
        packet_init(&pkt_remote);
        pkt_remote.len = ETH_FRAME_LEN;

        rc = packet_send(dev, sd, &pkt_local);
        check(rc != -1, "packet_send() failed");
        if (dhcp_action == DHCP_MESSAGE_TYPE_RELEASE)
                goto done;

        rc = packet_recv(sd, &pkt_remote, timeout);
        check(rc != -1, "packet_recv() failed");

        dhcp_print(pkt_remote.dhcp_header);

done:
        close(sd);
        return EXIT_SUCCESS;
error:
        if (sd) close(sd);
        return EXIT_FAILURE;
}
