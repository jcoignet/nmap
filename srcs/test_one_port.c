#include "ft_nmap.h"

void	ft_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
	struct tcphdr   *tcph;
	struct iphdr	*iph;
	struct icmphdr	*icmph;

	t_callback_data *cdata = (t_callback_data*)user;

	if (cdata->scan == SCAN_UDP) {
		cdata->state = STATE_CLOSED;
		return ;
	}
	tcph = (struct tcphdr*)(packet + sizeof(struct iphdr) + sizeof(struct ether_header));
	iph = (struct iphdr*)(packet + sizeof(struct ether_header));

	//if proto == TCP
	printf("proto %d icmp %d tcp %d\n", iph->protocol, IPPROTO_ICMP, IPPROTO_TCP);
	if (tcph->syn == 1 && tcph->ack == 1)//check bitwise ?
		cdata->state = STATE_OPEN;
	else if (tcph->ack == 1 && tcph->rst == 1)
		cdata->state = STATE_CLOSED;
	if (iph->protocol == IPPROTO_ICMP)
	{
	    icmph = (struct icmphdr*)(packet + sizeof(struct iphdr) + sizeof(struct ether_header));
	    printf("ICMP Type %d Code %d\n", icmph->type, icmph->code);
	}
	(void)pkthdr;
}

int	create_socket(t_scan scan)
{
	int	sock;

	if (scan == SCAN_UDP)
	{
		if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
		return -1;
	}
	else
	{
		if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		return -1;
	}

	return (sock);
}

t_pstate test_one_port(
	int port,
	char *ip_addr,
	struct addrinfo info,
	t_scan scan
) {
	char	*dev, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32	netp, maskp;
	pcap_t	*handle;
	struct bpf_program fp;	/* The compiled filter expression */
	char    *filter;
	int	    r, sock;

	sock = create_socket(scan);//ret
	if (sock < 0)
	fprintf(stderr, "sock failed [%s]\n", strerror(errno));

//	printf("Test port %s:%d by %ld\n", ip_addr, port, (long) pthread_self());
	asprintf(&filter, "src %s and src port %d", ip_addr, port);
	dev = strdup("eth0");
	/*dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
//		exit(EXIT_FAILURE);
	}*/

	pthread_mutex_lock(&pcap_compile_mutex);
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
//		exit(EXIT_FAILURE);
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, PCAP_TIMEOUT, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
//		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter, 0, netp) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
 //   	exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
//    	exit(EXIT_FAILURE);
	}
	pthread_mutex_unlock(&pcap_compile_mutex);

	t_callback_data cdata;
	cdata.state = STATE_BEING_TESTED;
	cdata.scan = scan;

	r = 0;
	ft_ping(port, sock, ip_addr, scan, info);
//	sleep(3);
	r = pcap_dispatch(handle, 0, ft_callback, (u_char*)&cdata);
	if (r == -1)
		fprintf(stderr, "port %d dispatch ret [%d] %s\n", port, r, strerror(errno));
	if (r == 0)
	{
		if (scan == SCAN_UDP)
			cdata.state = STATE_OPENFILTERED;
		else
			cdata.state = STATE_FILTERED;
		// ans->status = STATE_FILTERING;
		//fprintf(stderr, "port %d filtered\n", port->id);
	}
	pcap_close(handle);
	free(filter);
	close(sock);
	return (cdata.state);
}
