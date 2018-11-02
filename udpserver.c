#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "utilities.h"

#define MAX_MSG 512
#define MTUSIZE (2048-64*2)


struct state {
    int fd;
    struct mmsghdr messages[MAX_MSG];
    char buffer[MAX_MSG][MTUSIZE];
    struct iovec iovec[MAX_MSG];
};

struct state *init_state(struct state *s)
{
        int i;
        for(i=0; i<MAX_MSG; i++)
        {
            char *buf = &s->buffer[i][0];
            
            struct iovec *iovec = &s->iovec[i];
            struct mmsghdr *msg = &s->messages[i];

            msg->msg_hdr.msg_iov = iovec;
            msg->msg_hdr.msg_iovlen = 1;

            iovec->iov_base = buf;
            iovec->iov_len = sizeof(buf);
        }

        return s;
}

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

int bind_socket(struct net_addr *addr, int reuseport)
{
    int sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if(sd < 0) {
        PFATAL("socket()");
    }

    int one = 1;

    int r = setsockopt(sd, SOL_SOCKET,SO_REUSEADDR, (char *)&one, sizeof(one));
    if(r < 0){
        PFATAL("setsocket(SO_REUSEADDR)");
    }

    if(reuseport) {
            r = setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (char *)&one, sizeof(one));
            if(r < 0) {
                PFATAL("setsocket(SO_REUSEPORT)");
            }
    }

    if(bind(sd, addr->sockaddr, addr->sockaddr_len) < 0) {
            PFATAL("bind()");
    }

    return sd;
}

void set_buffer_size(int cd, int max)
{
    int i, flag = SO_RCVBUF;

    for(i=0; i<10; i++){
        int bef;
        socklen_t size = sizeof(bef);
        if(getsockopt(cd, SOL_SOCKET, flag, &bef, &size) < 0) 
        {
            PFATAL("getsockopt(SOL_SOCKET)");
        }

        if(bef >= max) {
            break;
        }

        size = bef * 2;
        if(setsockopt(cd, SOL_SOCKET, flag, &size, sizeof(size)) < 0){
            break;
        }
    }
}

void *thread_loop(void *data)
{
        struct state *st = data;

        fprintf(stderr, "CREATING RECEIEVER THREAD\n");

        while(1) 
        {
            int r = recvmmsg(st->fd, &st->messages[0], MAX_MSG, MSG_WAITALL, NULL);
            if(r < 0) {
                if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        continue;
                }
                PFATAL("recvmsg()");
            }

        }
}

int main(int argc, char *args[])
{
        const char *listener_addr = "0.0.0.0:4321";
        int recvbuf_size = 4*1024;
        int thread_num = 5;
        int reuseport = 0;

        switch(argc) 
        {
            case 2:
                thread_num = atoi(args[1]);
            case 1:
                break;
        }

        struct net_addr listen_addr;
        parse_addr(&listen_addr, listener_addr);

        int fd = -1;
        if(reuseport == 0) {
            fprintf(stderr, "Listening for updpackets on ip ; %s\n\n", listener_addr);

            fd = bind_socket(&listen_addr, 0);
            set_buffer_size(fd, recvbuf_size);
        }

        struct state *arr_states = calloc(thread_num, sizeof(struct state));

        int i;
        for(i=0; i<thread_num; i++)
        {
                struct state *st = &arr_states[i];
                init_state(st);
                st->fd = fd;

                pthread_t threadid;
                pthread_create(&threadid, NULL, thread_loop, st);
        }

        while(1) 
        {
        
        }
}