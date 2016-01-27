#include "ft_nmap.h"

void	ft_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    struct tcphdr   *tcph;
    t_callback_data *cdata = (t_callback_data*)user;

    if (cdata->scan == SCAN_UDP)
    {
	cdata->state = STATE_CLOSED;
	return ;
    }
    tcph = (struct tcphdr*)(packet + sizeof(struct iphdr) + sizeof(struct ether_header));
    //uint16_t	src_port, dst_port;
//    struct iphdr    *iph;
//    iph = (struct iphdr*)(packet + sizeof(struct ether_header));

//    src_port = ntohs(tcph->source);//ntohs(tcph->source);
    //dst_port = ntohs(tcph->dest);
    /*struct servent  *service = getservbyport(tcph->source, NULL);
    if (service != NULL)
    {
        printf("src %d dst %d SYN %d ACK %d RST %d service %s/%s\n",
	    src_port, dst_port, tcph->syn, tcph->ack, tcph->rst, service->s_name, service->s_proto);
	ans->service = ft_strjoin(service->s_name, service->s_proto);//+ service->s_proto !
    }
    else
    {
        printf("src %d dst %d SYN %d ACK %d RST %d\n",
	    src_port, dst_port, tcph->syn, tcph->ack, tcph->rst);
    }*/

    if (tcph->syn == 1 && tcph->ack == 1)//check bitwise ?
		cdata->state = STATE_OPEN;
    else if (tcph->ack == 1 && tcph->rst == 1)
		cdata->state = STATE_CLOSED;
    (void)pkthdr;
    (void)packet;
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

void test_one_port(t_nmap *nmap, t_port *port, char *ip_addr, t_scan scan)
{
    char	*dev, errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32	netp, maskp;
    pcap_t	*handle;
    struct bpf_program fp;	/* The compiled filter expression */
    char    *filter;
    int	    r, sock;

    sock = create_socket(scan);//ret
    if (sock < 0)
	fprintf(stderr, "sock failed [%s]\n", strerror(errno));

    printf("Test port %s:%d by %ld\n", ip_addr, port->id, (long) pthread_self());
    filter = ft_strjoin("src ", ip_addr);
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

    if (pcap_compile(handle, &fp, filter, 0, netp) == -1)
    {
    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
    	exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
    	fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
    	exit(EXIT_FAILURE);
    }

    t_callback_data cdata;

    cdata.state = STATE_BEING_TESTED;
    cdata.scan = scan;
    r= 0 ;
    ft_ping(port, sock, ip_addr, scan);
    //not udp or anyway i need scan for callbak or multiple callbak fn
    r = pcap_dispatch(handle, 0, ft_callback, (u_char*)&cdata);
	if (r == -1)
	    fprintf(stderr, "port %d dispatch ret [%d] %s\n", port->id, r, strerror(errno));
    if (r == 0)
    {
	if (scan == SCAN_UDP)
	    cdata.state = STATE_OPENFILTERED;
	else
	    cdata.state = STATE_FILTERED;
	    // ans->status = STATE_FILTERING;
	    //fprintf(stderr, "port %d filtered\n", port->id);
    }
    free(filter);
    close(sock);
    set_port_as_tested(nmap, port, cdata.state);
}
