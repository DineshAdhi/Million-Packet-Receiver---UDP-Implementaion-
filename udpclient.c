#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "utilities.h"

struct state {
    struct net_addr *target_addr;
    int packets_in_buf;
    const char *payload;
    int payload_size;
    int port;
};

void net_gethostbyname(struct net_addr *shost, const char *host, int port)
{
	memset(shost, 0, sizeof(struct net_addr));

	struct in_addr in_addr;

	if (inet_pton(AF_INET, host, &in_addr) == 1) {
		goto got_ipv4;
	}

	FATAL("inet_pton");

got_ipv4:
	shost->ipver = 4;
	shost->sockaddr = (struct sockaddr*)&shost->sin4;
	shost->sockaddr_len = sizeof(shost->sin4);
	shost->sin4.sin_family = AF_INET;
	shost->sin4.sin_port = htons(port);
	shost->sin4.sin_addr = in_addr;
}

void parse_addr(struct net_addr *netaddr, const char *addr) {
	char *colon = strrchr(addr, ':');
	if (colon == NULL) {
		FATAL("You forgot to specify port");
	}
	int port = atoi(colon+1);
	if (port < 0 || port > 65535) {
		FATAL("Invalid port number %d", port);
	}
	char host[255];
	int addr_len = colon-addr > 254 ? 254 : colon-addr;
	strncpy(host, addr, addr_len);
	host[addr_len] = '\0';
	net_gethostbyname(netaddr, host, port);
}

int connect_udp(struct net_addr *shost, int src_port)
{
	int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0) {
		PFATAL("socket()");
	}

	int one = 1;
	int r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&one,
			   sizeof(one));
	if (r < 0) {
		PFATAL("setsockopt(SO_REUSEADDR)");
	}

	if (src_port > 1 && src_port < 65536) {
		struct net_addr src;
		memset(&src, 0, sizeof(struct net_addr));
		char buf[32];
		snprintf(buf, sizeof(buf), "0.0.0.0:%d", src_port);
		parse_addr(&src, buf);
		if (bind(sd, src.sockaddr, src.sockaddr_len) < 0) {
			PFATAL("bind()");
		}
	}

	if (-1 == connect(sd, shost->sockaddr, shost->sockaddr_len)) {
		if (EINPROGRESS != errno) {
			PFATAL("connect()");
			return -1;
		}
	}

	return sd;
}

void thread_loop(void *userdata)
{
        struct state *state = userdata;

        struct mmsghdr *messages = calloc(state->packets_in_buf, sizeof(struct mmsghdr));
        struct iovec *iovecs = calloc(state->packets_in_buf, sizeof(struct iovec));

        int fd = connect_udp(state->target_addr, state->port);
        int i;

        for(i=0; i<state->packets_in_buf; i++)
        {
                struct mmsghdr *msg = &messages[i];
                struct iovec *iovec = &iovecs[i];

                msg->msg_hdr.msg_iov = iovec;
                msg->msg_hdr.msg_iovlen = 1;

                iovec->iov_base = (void *)state->payload;
                iovec->iov_len = state->payload_size;
        }

        fprintf(stderr, "SENDING PACKETS ......");

        while(1) 
        {
                int r = sendmmsg(fd, messages, state->packets_in_buf, 0);

                if(r <= 0) {
                        if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                                continue;
                        }

                        if(errno == ECONNREFUSED) {
                                continue;
                        }

                        perror("sendmsg()");
                }
        }
}

int main(int argc, char *args[])
{
        struct net_addr *addr = calloc(1, sizeof(struct net_addr));
        const char *ip = "172.20.25.233:4321";
        
        switch(argc)
        {
                case 2:
                        ip = args[1];
                case 1:
                        break;
        }

        parse_addr(&addr[0], ip);

        fprintf(stderr, "Sending to %s, send buffer %i packets\n\n", ip, 1024);

        const char *payload = (const char[32]){0};
        int payload_size = 32;

        struct state s;
        s.target_addr = addr;
        s.packets_in_buf = 1024;
        s.payload = payload;
        s.payload_size = payload_size;
        s.port = 11404;

        thread_loop(&s);
}
