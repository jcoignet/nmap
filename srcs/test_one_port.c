#include "ft_nmap.h"

t_pstate	tcp_packet_state(t_callback_data *cdata, struct tcphdr *tcph)
{
    if (cdata->scan == SCAN_UDP)
	return STATE_OPEN;
    if (tcph->rst == 1)
    {
	if (cdata->scan == SCAN_ACK)
	    return STATE_UNFILTERED;
	return STATE_CLOSED;
    }
    if (tcph->syn == 1)//ack too or not ?
	return STATE_OPEN;
    return STATE_FILTERED;
}

t_pstate	icmp_packet_state(t_callback_data *cdata, struct icmphdr *icmph)
{
    printf("got icmp t %d c %d\n", icmph->type, icmph->code);
    if (cdata->scan != SCAN_UDP)
	return STATE_FILTERED;
    if (icmph->type == 3 && icmph->code == 3)
	return STATE_CLOSED;
    return STATE_FILTERED;

}

void	ft_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
	struct iphdr	*iph;
	t_callback_data *cdata = (t_callback_data*)user;

	iph = (struct iphdr*)(packet + sizeof(struct ether_header));
	printf("PROTO %d (tcp %d udp %d icmp %d)\n", iph->protocol, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP);
	char	buf[256], buf2[256];
	printf("src %s dst %s\n", inet_ntop(AF_INET, &iph->saddr, buf, 256),
		inet_ntop(AF_INET, &iph->daddr, buf2, 256));
	if (iph->protocol == IPPROTO_TCP)
	{
		cdata->state = tcp_packet_state(cdata,
			(struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr)));
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
	    struct udphdr *udph = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	    printf("src port %d dst %d\n",
		    ntohs(udph->source), ntohs(udph->dest));
		if (cdata->scan == SCAN_UDP)
		    cdata->state = STATE_OPEN;
		else
		    cdata->state = STATE_FILTERED;
	}
	else if (iph->protocol == IPPROTO_ICMP)
	{
		cdata->state = icmp_packet_state(cdata,
			(struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr)));
	}
	else
		cdata->state = STATE_FILTERED;
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
	{
	    fprintf(stderr, "sock failed [%s]\n", strerror(errno));
	    return STATE_FILTERED;
	}

//	printf("Test port %s:%d by %ld\n", ip_addr, port, (long) pthread_self());
	if (scan == SCAN_UDP)
		asprintf(&filter, "src %s", ip_addr);//udp
	else
		asprintf(&filter, "src %s and src port %d", ip_addr, port);//else
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
		return STATE_FILTERED;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, PCAP_TIMEOUT, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return STATE_FILTERED;
	}

	if (pcap_compile(handle, &fp, filter, 0, netp) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		return STATE_FILTERED;
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		return STATE_FILTERED;
	}
	pthread_mutex_unlock(&pcap_compile_mutex);

	t_callback_data cdata;
	cdata.state = STATE_BEING_TESTED;
	cdata.scan = scan;

	r = 0;
	ft_ping(port, sock, ip_addr, scan, info);
	r = pcap_dispatch(handle, 0, ft_callback, (u_char*)&cdata);
	printf("port %d r = %d\n", port, r);
	if (r == -1)
		fprintf(stderr, "port %d dispatch ret [%d] %s\n", port, r, strerror(errno));
	if (r == 0)
	{
		if (scan == SCAN_SYN || scan == SCAN_ACK)
			cdata.state = STATE_FILTERED;
		else
			cdata.state = STATE_OPENFILTERED;
	}
	pcap_close(handle);
	free(filter);
	close(sock);
	return (cdata.state);
}
