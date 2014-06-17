/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "helper.h"

#define _VERSION_ "1.1"
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) > (b)) ? (a) : (b))

/* Two global variables to control command line options and termination. */
struct {
	char *ifname;
	in_addr_t filter;
	int layer;
} options;

int run;

/* Signal handler that interrupts the event loop. */
void
cleanup(int sig)
{
	fprintf(stderr,"\nReceived signal %d. Shutting down...\n",sig);
	run = 0;
}

/* Opens a raw socket, stores information in the sockaddr structure and returns
 * the socket descriptor or -1 on failure. */
int
open_raw_l2(struct sockaddr_ll *sa, const char *ifname)
{
	int sd;
	struct ifreq ifr;

	if (0 > (sd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))) {
		perror("socket() failed");
		return -1;
	}

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	if (0 > ioctl(sd,SIOCGIFINDEX,&ifr)) {
		perror("ioctl() failed");
		return -1;
	}

	memset(sa,0,sizeof(*sa));
	sa->sll_family		= PF_PACKET;
	sa->sll_protocol	= htons(ETH_P_ALL);
	sa->sll_ifindex		= ifr.ifr_ifindex;
	sa->sll_hatype		= ARPHRD_ETHER;
	sa->sll_pkttype		= PACKET_OTHERHOST;
	sa->sll_halen		= ETH_ALEN;

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	if (0 > ioctl(sd,SIOCGIFHWADDR,&ifr)) {
		perror("ioctl() failed");
		return -1;
	}
	memcpy(sa->sll_addr,ifr.ifr_hwaddr.sa_data,ETH_ALEN);

	if (0 > bind(sd,(struct sockaddr *)sa,sizeof(*sa))) {
		perror("bind() failed");
		return -1;
	}

	return sd;
}

int
open_raw_l3(struct sockaddr_in *sa, const char *ifname)
{
	int sd,optval;
	struct ifreq ifr;

	if (0 > (sd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))) {
		perror("socket() failed");
		return -1;
	}

	optval = 1;
	if( 0 > setsockopt(sd,IPPROTO_IP,IP_HDRINCL,&optval,
					sizeof(int)) ) {
	perror("setsockopt() failed");
	return -1;
	}

	memset(&ifr,0,sizeof(ifr));
	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
	if (0 > ioctl(sd,SIOCGIFADDR,&ifr)) {
		perror("ioctl() failed");
		return -1;
	}

	memset(sa,0,sizeof(*sa));
	sa->sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

	printf("%s\n", inet_ntoa(sa->sin_addr));
	sa->sin_family = AF_INET;

	if (0 > bind(sd,(struct sockaddr *)sa,sizeof(*sa))) {
		perror("bind() failed");
		return -1;
	}

	return sd;
}

/* Opens a domain socket, calls bind() and listen(), stores information in the
 * sockaddr structure and returns the socket descriptor or -1 on failure. */
int
open_dom(struct sockaddr_un *sa, const char *filename)
{
	int sd,slen;

	memset(sa,0,sizeof(*sa));
	sa->sun_family = AF_UNIX;
	strncpy(sa->sun_path,filename,sizeof(sa->sun_path));
	unlink(sa->sun_path);
	slen = sizeof(sa->sun_family) + strlen(sa->sun_path);

	if (0 > (sd=socket(AF_UNIX,SOCK_SEQPACKET,0))) {
		perror("socket() failed");
		return -1;
	}

	if (0 > bind(sd,(struct sockaddr *)sa,slen)) {
		perror("bind() failed");
		return -1;
	}

	if (0 > listen(sd,0)) {
		perror("listen() failed");
		return -1;
	}

	return sd;
}

/* Parses the command line arguments. Return 0 on success and -1 on error. */
int
parse_args(int argc, char **argv)
{
	char c;

	memset(&options,0,sizeof(options));
	options.filter = INADDR_NONE;
	options.layer  = 2;

	while (-1 != (c = getopt(argc,argv,"i:f:hl:"))) {
		switch(c) {
		case 'i':
			options.ifname = optarg;
			break;
		case 'f':
			options.filter = inet_addr(optarg);
			break;
		case 'l':
			options.layer = atoi(optarg);
			break;
		case 'h':
			return -1;
		default:
			abort();
		}
	}

	if (NULL == options.ifname)
		return -1;
	if (options.layer != 2 && options.layer != 3)
		return -1;

	return 0;

}

/* Prints the help banner. */
void
print_help(const char *name)
{
	fprintf(stdout,"\n");
	fprintf(stdout,"moep8023 v%s\n\n",_VERSION_);
	fprintf(stdout,"Usage: %s -i <interface> [-f <ipv4 address>] [-l <2|3>]\n",name);
	fprintf(stdout,"    -i <interface>:    Sets the interface used for"
		"monitoring/injection.\n");
	fprintf(stdout,"    -f <ipv4 address>: Specifies an address filter, "
		"i.e., packets destined to or received from that address are "
		"not printed.\n");
	fprintf(stdout,"    -l <2|3>:          Specifies whether layer 2 frames "
		"including the link-layer header or IP packets including IP header "
		"but without link-layer header are passed to moep8023. If this "
		"option is omitted, the former case is assumed. If -l3 is chosen, "
		"moep8023 will automatically contract a suitable link-layer header "
		"based on the next-hop address for the IP destination given in the "
		"packet.\n");
	fprintf(stdout,"\n");
}


int
l3send(int sd_ll, const unsigned char *buffer, int len, int flags)
{
	struct sockaddr_in sa;
	struct iphdr *ip_hdr;
	int ret;

	memset(&sa,0,sizeof(sa));
	ip_hdr = (struct iphdr *)buffer;
	memcpy(&sa.sin_addr,&ip_hdr->daddr,sizeof(ip_hdr->daddr));	

	ret = sendto(sd_ll,buffer,len,flags,(struct sockaddr *)&sa,
			sizeof(sa));

	if (0 > ret)
		perror("sendto failed");
	else 
		fprintf(stdout,"SENT %d byte\n",ret);

	return ret;
}


int
main(int argc, char **argv)
{
	struct sockaddr_ll sa_ll;
	struct sockaddr_in sa_in;
	struct sockaddr_ll sa_from;
	struct sockaddr_un sa_dom_srv;
	struct sockaddr_un sa_dom;
	struct iphdr *ip_hdr;
	struct ethhdr *eth_hdr;
	ssize_t len;
	socklen_t slen,sa_dom_len;
	fd_set rfds,rfd;
	int ret,maxfd,sd_ll,sd_in,sd_dom_srv,sd_dom;

	memset(&sa_dom,0,sizeof(sa_dom));
	memset(&sa_dom_len,0,sizeof(sa_dom_len));

	/* This is our frame buffer */
	unsigned char buffer[ETH_FRAME_LEN];

	slen = sizeof(sa_from);

	(void)signal(SIGINT,cleanup);
	(void)signal(SIGTERM,cleanup);

	if (0 > parse_args(argc,argv)) {
		print_help(argv[0]);
		return 0;
	}

	/* This is the link-layer socket used to receive anything and to
           L2 frames if -l3 is not specified on the command line. */
	if (0 > (sd_ll = open_raw_l2(&sa_ll,options.ifname))) {
		fprintf(stderr,"open_raw() failed\n");
		return -1;
	}

	/* This is the ip raw socket used to send packets if and only if
           -l3 was specified on the command line. Otherwise the socket is
           not being used. */
	if (0 > (sd_in = open_raw_l3(&sa_in,options.ifname))) {
		fprintf(stderr,"open_raw() failed\n");
		return -1;
	}

	if (0 > (sd_dom_srv = open_dom(&sa_dom_srv,"moep8023_socket"))) {
		fprintf(stderr,"open_dom() failed\n");
		return -1;
	}
	fprintf(stdout,">> Raw link layer socket (fd=%d) opened on %s\n",
					sd_ll,options.ifname);
	fprintf(stdout,">> Raw ip socket (fd=%d) opened on %s\n",
					sd_in,options.ifname);
	
	FD_ZERO(&rfds);
	FD_SET(sd_dom_srv,&rfds);
	FD_SET(sd_ll,&rfds);
	maxfd = MAX(sd_ll,sd_dom_srv);

	sd_dom = -1;

	run = 1;
	/* Event loop: runs while run == 1 */
	while (run) {
		rfd = rfds;

		ret = select(maxfd+1,&rfd,NULL,NULL,NULL);
		if (0 > ret) {
			if (errno == EINTR)
				continue;
			perror("select() failed");
			run = 0;
		}

		/* Check the listining socket for incoming connections. */
		if (FD_ISSET(sd_dom_srv,&rfd)) {
			/* New client, accept() and add him. */
			sd_dom=accept(sd_dom_srv,(struct sockaddr*)&sa_dom,
					&sa_dom_len);
			if (0 > sd_dom) {
				perror("accept() failed");
				run = 0;
			}

			FD_SET(sd_dom,&rfds);
			maxfd = MAX(maxfd,sd_dom);

			fprintf(stdout,">> client connected to %s\n",
					sa_dom_srv.sun_path);
		}

		/* Read something from the raw socket */
		if (FD_ISSET(sd_ll,&rfd)) {
			len = recvfrom(sd_ll,buffer,ETH_FRAME_LEN,0,
					(struct sockaddr *)&sa_from,&slen);

			if (0 > len) {
				perror("recv() failed");
				run = 0;
			}

			eth_hdr = (struct ethhdr *)buffer;
			ip_hdr = (struct iphdr*)(buffer+sizeof(struct ethhdr));
			
			/* Make sure not to handle this frame if it was either
			   excluded via filter or we find our own source address */	
			if (ip_hdr->saddr == options.filter ||
			    ip_hdr->daddr == options.filter ||
			    0 == memcmp(eth_hdr->h_source,sa_ll.sll_addr,ETH_ALEN))
				continue;

			fprintf(stdout,">> received %d B from %s:\n",(int)len,
					options.ifname);
			hexdump(buffer,len);

			/* If no client is connected, continue. */
			if (sd_dom < 0)
				continue;

			/* Relay frame to the client. */
			ret = send(sd_dom,buffer,len,MSG_DONTWAIT);
			if (0 >= ret) {
				FD_CLR(sd_dom,&rfds);
				close(sd_dom);
				sd_dom = -1;

				fprintf(stdout,"client disconnected from %s\n",
						sa_dom_srv.sun_path);

				continue;
			}

			fprintf(stdout,">> sent %d B to %s\n",ret,
				sa_dom_srv.sun_path);

			/* Sanity check */
			if (ret != len) {
				fprintf(stderr,"WARNING: partial send (%d"
						" %d B)",ret,(int)len);
				if (errno == EWOULDBLOCK)
					fprintf(stderr," (send would block)");
				fprintf(stderr,"\n");
			}
		}

		/* Read something from the client. */
		if (FD_ISSET(sd_dom,&rfd)) {
			len = recv(sd_dom,buffer,ETH_FRAME_LEN,0);
			if (0 >= len) {
				FD_CLR(sd_dom,&rfds);
				close(sd_dom);
				sd_dom = -1;

				fprintf(stdout,"client disconnected from %s\n",
						sa_dom_srv.sun_path);

				continue;
			}

			fprintf(stdout,">> received %d B from %s:\n",(int)len,
					sa_dom_srv.sun_path);
			hexdump(buffer,len);

			/* Try to relay it to the raw socket. */
			if (options.layer == 3)
				ret = l3send(sd_in,buffer,len,0);
			else
				ret = sendto(sd_ll,buffer,len,0,
					(struct sockaddr *)&sa_ll,
					sizeof(sa_ll));

			fprintf(stdout,">> sent %d B to %s\n",ret,
				options.ifname);

			/* Sanity check */
			if (ret != len) {
				fprintf(stderr,"WARNING: partial send (%d"
						" of %d B)\n",ret,(int)len);
			}
		}

	}

	/* Tidy up and unlink the domain socket */
	close(sd_ll);
	close(sd_in);
	if (FD_ISSET(sd_dom,&rfds))
		close(sd_dom);
	close(sd_dom_srv);
	unlink(sa_dom_srv.sun_path);

	fprintf(stderr,"Shutdown complete.\n\n");

	return 0;
}

