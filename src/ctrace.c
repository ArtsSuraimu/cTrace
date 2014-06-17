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

/*
 * This Program is based on ctrace example provided by the Chair of Computer Network.
 * 2013 by Clemens Jonischkeit and Dai Yang
 * Technical University Munich Faculty of Computer Science
 * Traceroute implemted in C.
 * Current defined max TTL is 64, attemps per hop is 5, and if tree hops did not provide
 * proper answer, then exit.  
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
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>


#define _VERSION_ "1.1"

#define _TTL_MAX 64
#define _MAX_ATTEMP 5
#define _MAX_SILENT 3

#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#define MIN(a,b) (((a) > (b)) ? (a) : (b))

/* Two global variables to control command line options and termination. */
struct {
 	char *filename;
 	char *target;
 	char *ifname;
} options;

int _run;

/* Signal handler that interrupts the event loop. */
void
cleanup(int sig)
{
   	fprintf(stderr,"\nReceived signal %d. Shutting down...\n",sig);
  	_run = 0;
}

/* Connects to a domain socket. Socket information is stored in the sockaddr
 * structure, filename is the path to the domain socket we want to connect to.
 * Returns the socket descriptor or -1 on error. */
int
connect_dom(struct sockaddr_un *sa, const char *filename)
{
 	int sd,slen;

  	memset(sa,0,sizeof(*sa));
  	sa->sun_family = AF_UNIX;
 	strncpy(sa->sun_path,filename,sizeof(sa->sun_path));
 	slen = sizeof(sa->sun_family) + strlen(sa->sun_path);

 	if (0 > (sd=socket(AF_UNIX,SOCK_SEQPACKET,0)) ) {
   	  	perror("socket() failed");
 	  	return -1;
  	}
 	if (0 > connect(sd,(struct sockaddr *)sa,slen)) {
 	 	perror("connect() failed");
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

 	while (-1 != (c = getopt(argc,argv,"s:t:i:h"))) {
 	   	switch(c) {
  	 	case 's':
  	  	 	options.filename = optarg;
 	 	   	break;
  	 	case 't':
  	  	 	options.target = optarg;
 	 	   	break;
  	 	case 'i':
  	  	 	options.ifname = optarg;
 	 	   	break;
  	 	case 'h':
  	  	 	return -1;
 	 	default:
   	  	 	abort();
  	  	}
 	}

 	if (NULL == options.filename || NULL == options.target)
 	   	return -1;

  	return 0;

}

/* Prints the help banner. */
void
print_help(const char *name)
{
 	fprintf(stdout,"\n");
  	fprintf(stdout,"TraceRoute based on C.  v%s\n\n",_VERSION_);
	printf("Author: Clemens Jonischkeit, Dai Yang.\n");
  	fprintf(stdout,"Usage: %s -s <socket> -i <interface> "
 	 	"-t <target>\n",name);
 	fprintf(stdout,"    -s <socket>:    Sets path/filename of the domain"
   	  	"socket we want to connect to.\n");
 	fprintf(stdout,"    -i <interface>: Sets the interface name from "
  	  	"packets should be sent. This is neccessary to determine the "
 	 	"correct source IP address of packets. Note that this value "
 	   	"should be the same one as for moep8023.\n");
  	fprintf(stdout,"    -t <target>:    Target IP address that should be "
 	  	"traced.\n");
  	fprintf(stdout,"    -h:             Prints this message.\n");
 	fprintf(stdout,"\n");
}

int
getInterfaceIp(struct in_addr *addr, const char *ifname)
{
 	struct ifreq ifr;
 	int sd;
   	
  	if (0 > (sd=socket(AF_INET,SOCK_DGRAM,0)) ) {
 	  	perror("socket() failed");
  	 	return -1;
 	}

 	memset(&ifr,0,sizeof(ifr));
   	strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
  	if (0 > ioctl(sd,SIOCGIFADDR,&ifr)) {
 	  	perror("ioctl() failed");
  	 	return -1;
 	}

 	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

   	return 0;
}

/* Receives up to max_len bytes from moep8023 and stores it in the region
   pointed to by buffer. The socket descriptor sd is expected to be a valid
   connection-oriented socket of type SOCK_SEQPACKET that points to moep8023.
   The timeout points to a struct timeval that indicates the maximum amount of
   time doRecv() should wait for incoming packets before returning. A return
   value of -1 indicates an eroor, 0 indicates a timeout, any positive value
   smaller or equal to max_len indicates the number of bytes received, and for
   any larger value than max_len you may blame the teaching assistant.
   */
int
doRecv(int sd, void *buffer, ssize_t max_len, struct timeval *timeout)
{
  	int ret,len = 0;
 	fd_set rfds;

  	FD_ZERO(&rfds);
  	FD_SET(sd,&rfds);

 	if (0 > (ret=select(sd+1,&rfds,NULL,NULL,timeout))) {
 	 	if (errno != EINTR) {
   	  	 	perror("select() failed");
  	  	 	return -1;
 	 	}
   	}
  	else if (FD_ISSET(sd,&rfds)) {
 	  	memset(buffer,0,max_len);
  	 	len = recv(sd,buffer,max_len,0);

 	 	if (0 > len) {
   	  	 	perror("recv() failed");
  	  	 	return -1;
 	 	}
   	}
  	else {
 	  	// timeout
  	 	return 0;
 	}

 	return len;
}


/* Tries to send len bytes from from buffer to moep8023.  The socket descriptor
   sd is expected to be a valid connection-oriented socket of type
   SOCK_SEQPACKET that points to moep8023.  A return value of -1 indicates an
   eroor, 0 indicates a timeout, any positive value smaller or equal to len
   indicates the number of bytes written to moep8023, and for any larger value
   than max_len you may blame the teaching assistant. Note that
   - also unlikely - handling the case of partial writes, i.e., send() was
   interrupted, is up to you. Quite sure you can ignore that case and consider
   the packet as lost.  */
int
doSend(int sd, void *buffer, ssize_t len)
{
   	int ret;

  	if (0 > (ret=send(sd,buffer,len,0))) {
 	  	perror("send() failed");
  	 	return -1;
 	}

 	return ret;
}


/* Returns the IP/ICMP checksum calculated over the memory region of length len
   pointed to by addr. Return value is the 16 bit checksum. */
short
in_cksum(u_int16_t *addr, int len) {
        register int sum      = 0;
        short ret             = 0;
        register u_int16_t *w = addr;
        register int nleft    = len;

        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }

        if (nleft == 1) {
                *(u_char *) (&ret) = *(u_char *) w;
                sum += ret;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        ret = ~sum;
        return ret;
}

/* Converts the target IP address given as character array pointed to by target
   into a struct in_addr binary representation in network byte order pointed to
   by addr. Return 0 on succes and -1 on err. */
int
getTargetIp(const char *target, struct in_addr *addr)
{
   	struct hostent *he;
  	struct in_addr **addr_list;
 	int i;

  	if (NULL == (he=gethostbyname(target))) {
  	 	herror("gethostbyname() failed");
 	 	return 1;
   	}

  	addr_list = (struct in_addr **) he->h_addr_list;

 	/* may be the target has multiple ips, return the first one */
  	for (i=0; addr_list[i]!=NULL; i++) {
  	 	addr->s_addr = addr_list[i]->s_addr;
 	 	return 0;
   	}

  	return -1;
}

/* For your convinience, this function creates a fully-featured IP-header from
   the values supplied and stores it in the memory region pointed to by buffer.
   The header checksum is calculated automatically. Note that we set the DF bit
   to avoid fragmentation of our packets. */
void
buildIpHeader(void *buffer, struct in_addr sha, struct in_addr tha,
 	  	unsigned char ttl, short identifier, char protocol, short plen)
{
  	struct iphdr *ip_hdr = buffer;

 	memset(ip_hdr,0,sizeof(*ip_hdr));

 	ip_hdr->ihl      = 0x5;
 	ip_hdr->version  = 0x4;
   	ip_hdr->tot_len  = htons(plen + sizeof(*ip_hdr));
  	ip_hdr->id       = htons(identifier);
 	ip_hdr->ttl      = ttl;
  	ip_hdr->protocol = protocol;
  	ip_hdr->saddr    = sha.s_addr;
 	ip_hdr->daddr    = tha.s_addr;
 	ip_hdr->frag_off = htons(0x1 << 14); // don't fragment

 	ip_hdr->check = in_cksum((u_int16_t *)ip_hdr,sizeof(*ip_hdr));
}

/* Also for your convenience, this function creates a valid ICMP echo request
   packet, including ICMP header and checksum. Note that the checksum does cover
   the payload, which differs from the IP header checksum. If your ICMP packet
   shall not have a payload, you may supply plen=0. */
void
buildIcmpEchoRequest(void *buffer, unsigned short id, 
   	  	unsigned short seq, int plen)
{
 	struct icmphdr *icmp_hdr = buffer;

  	memset(icmp_hdr,0,sizeof(*icmp_hdr));

  	icmp_hdr->type             = ICMP_ECHO;
 	icmp_hdr->code             = 0;
 	icmp_hdr->un.echo.id       = htons(id);
 	icmp_hdr->un.echo.sequence = htons(seq);
   	
  	icmp_hdr->checksum = in_cksum((u_int16_t *)icmp_hdr,
 	  	  	 	sizeof(*icmp_hdr) + plen);
}

/* This where the funny part starts. */
int
run()
{
 	struct sockaddr_un sun;
 	struct in_addr myIp;
   	struct in_addr targetIp;
  	/* You need these pointer, think about them until you got it. */
 	struct iphdr   *ip_hdr   = NULL, *ip_rpl_hdr = NULL;
  	struct icmphdr *icmp_hdr = NULL, *icmp_rpl_hdr = NULL;
  	struct ethhdr  *eth_hdr  = NULL;
 	unsigned char  *payload  = NULL;
 	/* You also need this timeout. */
 	struct timeval timeout;
   	int len;
  	int ret,sd;
 	int totlen;
  	int plen;
	int try,failed,ttl,tmp;
	unsigned short seq,id;
	unsigned char *src_ip;

 	/* This is our frame/packet (did you know iabout the difference between
 	   frames and packets?) buffer */
 	unsigned char buffer[ETH_FRAME_LEN];

   	/* Getting a little paranoid when passing uninitialzed return valus
  	   to libc functions... gcc rulezzz */
 	memset(&sun,0,sizeof(sun));
  	if (0 > (sd = connect_dom(&sun,options.filename))) {
  	 	fprintf(stderr,"connect_dom() failed\n");
 	 	return -1;
   	}
  	fprintf(stdout,">> Connected to %s (fd=%d)\n",options.filename,sd);

 	if (0 != getInterfaceIp(&myIp,options.ifname)) {
  	  	fprintf(stderr,"getInterfaceIp() failed\n");
 	 	return -1;
 	}
        if( 0 != getTargetIp(options.target,&targetIp)) {
   	  	fprintf(stderr,"getTargetIp() failed\n");
 	  	return -1;
  	}

 	fprintf(stdout, "IP of local interface %s is %s\n",options.ifname,
 	 	   	  	 	  	inet_ntoa(myIp));
  	fprintf(stdout, "IP of target is %s\n",inet_ntoa(targetIp));
	
 	/* Define sequence number and identifier of our echo request */
  	seq = 0;
  	id = rand();

 	/* Fill the packet payload with random stuff such that a neat 64 B
 	   packet is sent */
 	plen = 64 - sizeof(*ip_hdr) - sizeof(*icmp_hdr); // makes 64 byte

	failed = 0;
	for(ttl=1; ttl < _TTL_MAX ; ttl++){	//Max Hop Definition
		
		for(try = 0; try < _MAX_ATTEMP; try++){		//trys per hop
			id = rand();
			
			/* Initialize packet buffer and set header pointers */
 			memset(buffer,0,sizeof(buffer));
 			ip_hdr = (struct iphdr *)buffer;
  		 	icmp_hdr = (struct icmphdr *)((void *)buffer + sizeof(*ip_hdr));
  			payload = (unsigned char *)((void *)icmp_hdr + sizeof(*icmp_hdr));

			for (tmp=0; tmp<plen; tmp++)
		  	 	payload[tmp] = (unsigned char)(tmp & 0xff);

			//build the packet
			buildIcmpEchoRequest(icmp_hdr,id,seq,plen);
			buildIpHeader(ip_hdr,myIp,targetIp,ttl,rand(),IPPROTO_ICMP,
					sizeof(*icmp_hdr) + plen);

			// Calculate total length of the packet
			totlen = plen + sizeof(*icmp_hdr) + sizeof(*ip_hdr);



			if (0 > (ret = doSend(sd,buffer,totlen))) {
 	 			perror("send() failed");
 	   			return 1;
  			}
 			//Sent ICMP Echo request


			/* We wait at for an answer.*/
 			timeout.tv_sec = 1;
 			timeout.tv_usec = 0;

   			_run = 1;
  			/* Event loop: _runs while _run == 1 */ 	
		  	while (_run == 1) {
  	 			/* Try to receive something. */
		 	 	len = doRecv(sd,buffer,sizeof(buffer),&timeout);
   	  			if (0 > len && errno != EINTR) {
		 	  	  	fprintf(stderr,"doRecv() failed\n");
 	 			 	_run = -1;
		   	  	}
		 	  	if (0 == len) {
		  	 	 	fprintf(stderr,"Hop %i:\tRequest time out...\n",ttl);
		 	   	  	_run = -1;
		 	  	}
		
		  	 	/* checkout the answer */
		 	 	eth_hdr = (struct ethhdr *)buffer;
				if (eth_hdr->h_proto != htons(0x0800))
		 	  	  	continue;
		 	 	//got IP packet
		
		 	   	ip_hdr = (struct iphdr *)(buffer+sizeof(*eth_hdr));  	
		 	  	if (ip_hdr->protocol != IPPROTO_ICMP)
		  	 	 	continue;
		 	   	//got ICMP packet
		
				icmp_hdr = (struct icmphdr *)((void *)ip_hdr+sizeof(*ip_hdr));
				
				ip_rpl_hdr = (struct iphdr *)((void *)icmp_hdr + sizeof(*icmp_hdr));;				
				icmp_rpl_hdr = (struct icmphdr *)((void *)ip_rpl_hdr + sizeof(*ip_rpl_hdr));
				src_ip = (unsigned char*)((void*)&(ip_hdr->saddr));

		  	  	if (icmp_hdr->type == 0 && icmp_hdr->code == 0){
		
					if (icmp_hdr->un.echo.id == htons(id) &&
					    icmp_hdr->un.echo.sequence == htons(seq)) {
						fprintf(stdout,"Hop %i:\t%hhu.%hhu.%hhu.%hhu\nDestination Reached\n",
							ttl,src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
				 	   	_run = 0;
		  			}
				}
				//If the response is from the final destination


				if(icmp_hdr->type == 11 && icmp_hdr->code == 0){
					if(icmp_rpl_hdr->un.echo.id == htons(id) 
								&& icmp_rpl_hdr->un.echo.sequence == htons(seq)){
						fprintf(stdout,"Hop %i:\t%hhu.%hhu.%hhu.%hhu\n",ttl,src_ip[0],src_ip[1],
				  							       src_ip[2],src_ip[3]);
						_run = 2;
						failed = 0;
					}
				}
			}	// rcv - while schleife
			if(_run == 0 || _run == 2)
				break;
		}	// try schleife
		if(_run == 0)
			break;
		if(try == 5)
			failed++;
		if(failed >=_MAX_SILENT){
			_run = 1;
			fprintf(stdout,"Max attempts reached. Host not reachable.");
			break;
		}
	}	// ttl schleife
	
	if(ttl == 64){
		fprintf(stdout,"Host not reachable");
	}


  	close(sd);

  	return _run;
}

/* The main() doesn't do much except for registering the signal handler for a
   clean shutdown when SIGINT/SIGTERM is received. */
int
main(int argc, char **argv)
{
 	(void)signal(SIGINT,cleanup);
 	(void)signal(SIGTERM,cleanup);

 	if (0 > parse_args(argc,argv)) {
   	  	print_help(argv[0]);
 	  	return 0;
  	}

 	return run();
}

