#include "ft_nmap.h"

void	ft_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    struct tcphdr   *tcph;
    //uint16_t	src_port, dst_port;
    t_pstate *port_state = (t_pstate*)user;
//    struct iphdr    *iph;

//    iph = (struct iphdr*)(packet + sizeof(struct ether_header));
    tcph = (struct tcphdr*)(packet + sizeof(struct iphdr) + sizeof(struct ether_header));

    //src_port = ntohs(tcph->source);//ntohs(tcph->source);
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
		*port_state = STATE_OPEN;
    else if (tcph->ack == 1 && tcph->rst == 1)
		*port_state = STATE_CLOSE;
    (void)pkthdr;
    (void)packet;
}

int	create_socket(void)//tcp or udp
{
	int	sock;
	int	i = 1;
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	    return -1;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) < 0)
	    return -1;

	return (sock);
}

void test_one_port(t_nmap *nmap, t_port *port, char *ip_addr)
{
    char	*dev, errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32	netp, maskp;
    pcap_t	*handle;
    struct bpf_program fp;	/* The compiled filter expression */
    char    *filter;
    int	    r, sock;

    //open socket
    sock = create_socket();//ret
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

    // t_answer	*ans = malloc(sizeof(t_answer));
    // ans->port = nmap->tport;
    // ans->service = NULL;
    t_pstate port_state = STATE_BEING_TESTED;
    r= 0 ;
    ft_ping(port, sock);
    r = pcap_dispatch(handle, 0, ft_callback, (u_char*)&port_state);
//	if (r == -1)
//	    fprintf(stderr, "port %d dispatch ret [%d] %s\n", nmap->tport, r, strerror(errno));
    if (r == 0)
    {
	port_state = STATE_FILTERING;
	    // ans->status = STATE_FILTERING;
	    //fprintf(stderr, "port %d filtered\n", port->id);
    }
    set_port_as_tested(nmap, port, port_state);
}
