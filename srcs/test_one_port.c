#include "ft_nmap.h"

t_pstate	tcp_packet_state(t_callback_data *cdata, struct tcphdr *tcph)
{
    if (cdata->scan == SCAN_UDP)
	return STATE_OPEN;
    if (tcph->rst == 1)
    {
	if (cdata->scan == SCAN_ACK)
	    return STATE_UNFILTERED;
	else if (cdata->scan == SCAN_WIN)
	{
	    if (tcph->window == 0)
		return STATE_CLOSED;
	    else
		return STATE_OPEN;
	}
	return STATE_CLOSED;
    }
    if (tcph->syn == 1 || tcph->ack == 1)
	return STATE_OPEN;
    return STATE_FILTERED;
}

t_pstate	icmp_packet_state(t_callback_data *cdata, struct icmphdr *icmph)
{
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
	if (iph->protocol == IPPROTO_TCP)
	{
		cdata->state = tcp_packet_state(cdata,
			(struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr)));
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
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
	t_scan scan,
	int timeout,
	char *saddr,
	char *dev,
	int islocal
) {
	char	errbuf[PCAP_ERRBUF_SIZE];
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
	if (islocal == 1)
		dev = strdup("lo");
	if (scan == SCAN_UDP)
		asprintf(&filter, "(icmp and src %s) or (src %s and src port %d)", ip_addr, ip_addr, port);//udp
	else
		asprintf(&filter, "(icmp and src %s) or (tcp and src %s and src port %d)", ip_addr, ip_addr, port);//else

	pthread_mutex_lock(&pcap_compile_mutex);
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		return STATE_FILTERED;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, timeout, errbuf);
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
	ft_ping(port, sock, ip_addr, scan, info, saddr, islocal);
	int to = timeout / 1000;
	if (to <= 0)
	    to = 1;
	while (to > 0 && r == 0)
	{
		r = pcap_dispatch(handle, 1, ft_callback, (u_char*)&cdata);
		to--;
	}
//	printf("port %d r = %d\n", port, r);
	if (r == -1)
		fprintf(stderr, "port %d dispatch ret [%d] %s\n", port, r, strerror(errno));
	if (r == 0)
	{
		if (scan == SCAN_SYN || scan == SCAN_ACK || scan == SCAN_WIN)
			cdata.state = STATE_FILTERED;
		else
			cdata.state = STATE_OPENFILTERED;
	}
	pcap_close(handle);
	free(filter);
	close(sock);
	return (cdata.state);
}
