#include <iostream>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "listener.hpp"

using namespace hypervision;

#define BUFFER_SIZE 65536

typedef unsigned char byte_t;

Listener::Listener(const std::string &iface) {
	sock_recv = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	buffer = (byte_t *)malloc(sizeof(byte_t) * BUFFER_SIZE);

	if (sock_recv < 0) {
		perror("sock_recv creation failed");
		exit(1);
	}

	struct sockaddr_ll saddr;
	memset(&saddr, 0, sizeof(struct sockaddr_ll));

	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = if_nametoindex(iface.c_str());

	if (bind(sock_recv, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("sock_recv bind failed");
		close(sock_recv);
		exit(1);
	}

	printf("Listening to interface %s...\n", iface.c_str());
	fflush(stdout);
}

Listener::~Listener() {
	close(sock_recv);
}

sample_t Listener::receive_sample() {
	struct sockaddr_ll saddr;
	auto saddr_size = sizeof(struct sockaddr);

	auto data_size =
		recvfrom(sock_recv, buffer, BUFFER_SIZE, 0,
				 (struct sockaddr *)&saddr, (socklen_t *)&saddr_size);

	if (data_size < 0) {
		printf("Error: Recvfrom failed to get packets.\n");
	}

	auto pkt = (pkt_hdr_t *)(buffer);

	return sample_t(pkt, data_size);
}
