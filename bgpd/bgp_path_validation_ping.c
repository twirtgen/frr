//
// Created by thomas on 4/05/22.
//

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <errno.h>

#include "lib/if.h"

#include "bgpd/bgp_path_validation_ping.h"

// Define the Packet Constants
// ping packet size
#define PING_PKT_S 64

// Automatic port number
// #define PORT_NO 0


// ping packet structure
struct ping_pkt {
	struct icmphdr hdr;
	char msg[PING_PKT_S - sizeof(struct icmphdr)];
};

// Calculating the Check Sum
static unsigned short checksum(void *b, int len) {
	unsigned short *buf = b;
	unsigned int sum;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}


// make a ping request
int send_ping(struct sockaddr_in *ping_addr, unsigned int timeout_us,
	      unsigned int retries, const char *iface_name) {
	unsigned int i;
	int ttl_val = 64, msg_count = 0, flag,
	    msg_received_count = 0;
	int ping_sockfd;
	struct ping_pkt pckt;
	struct sockaddr_in r_addr;
	struct timeval tv_out;
	socklen_t addr_len;
	const char *err;
	int ret = -1;
	int ok = 0;

	tv_out = (struct timeval) {
		.tv_sec = 0,
		.tv_usec = timeout_us,
	};

	// socket()
	ping_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (ping_sockfd < 0) {
		perror("socket SOCK_RAW IPPROTO_ICMP");
		goto end;
	}


	// set socket options at ip to TTL and value to 64,
	// change to what you want by setting ttl_val
	if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val,
		       sizeof(ttl_val)) != 0) {
		printf("\nSetting socket options to TTL failed!\n");
		goto end;
	}

	// set output interface
	if (setsockopt(
		    ping_sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface_name,
		    strnlen(iface_name, IF_NAMESIZE)) == -1) {
		err = strerror(errno);
		fprintf(stderr, "PING SO_BINDTODEVICE %s error: %s\n",
			iface_name, err);
		goto end;
	}

	// setting timeout of recv setting
	if (setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO,
		       (const char *)&tv_out, sizeof tv_out) != 0) {
		perror("Setsockopt SOL_SOCKET SO_RCVTIMEO");
		goto end;
	}

	// send icmp packet
	while (retries > 0 && !ok) {
		// flag is whether packet was sent or not
		flag = 1;

		// filling packet
		bzero(&pckt, sizeof(pckt));

		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = getpid();

		for (i = 0; i < sizeof(pckt.msg) - 1; i++)
			pckt.msg[i] = i + '0';

		pckt.msg[i] = 0;
		pckt.hdr.un.echo.sequence = msg_count++;
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

		// send packet
		if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0,
			   (struct sockaddr *)ping_addr,
			   sizeof(*ping_addr)) <= 0) {
			printf("\nPacket Sending Failed!\n");
			flag = 0;
		}

		// receive packet
		addr_len = sizeof(r_addr);

		if (recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0,
			     (struct sockaddr *)&r_addr, &addr_len) > 0 ||
		    msg_count <= 1) {
			// if packet was not sent, don't receive
			if (flag) {
				if (!(pckt.hdr.type == 69 &&
				      pckt.hdr.code == ICMP_ECHOREPLY)) {
					printf("Error..Packet received with ICMP type %d code %d\n",
					       pckt.hdr.type, pckt.hdr.code);
				} else {
					msg_received_count++;
					ok = 1;
				}
			}
		}
		retries -= 1;
	}

	ret = 0;

end:
	if (ping_sockfd >= 0) {
		close(ping_sockfd);
	}
	return ret;
}