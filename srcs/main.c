/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcoignet <jcoignet@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:39 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/22 13:01:57 by jcoignet         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		addr_info(t_nmap *nmap)
{
	struct addrinfo		*info;
	char			buf[IP_BUFFLEN];
	struct hostent		*client;
	char			*fqdn;

	if (getaddrinfo(nmap->hostname, NULL, NULL, &info) != 0)
	{
		fprintf(stderr, "ft_nmap: unknown host %s\n", nmap->hostname);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET,
			(void*)&(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr),
			buf,IP_BUFFLEN);
	nmap->hostip = ft_strdup(buf);
	nmap->info = info;
	((struct sockaddr_in*)(nmap->info->ai_addr))->sin_port = nmap->tport;
	client = gethostbyaddr((void*)&(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr),
		sizeof(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr), AF_INET);
	if (client == NULL || client->h_name == NULL)
	    fqdn = strdup(nmap->hostname);
	else
	    fqdn = strdup(client->h_name);
	printf("ft_nmap scan report for %s (%s)\n", nmap->hostname, buf);
	//host is up + ping
	printf("rDNS record for %s: %s\n\n", buf, fqdn);
}

void	nmap_header(char *progname)
{
    struct timeval  tv;
    char	    buf[128];

    if (gettimeofday(&tv, NULL) == -1)
    {
	fprintf(stderr, "%s: gettimeofday error: %s\n", progname, strerror(errno));
	exit(EXIT_FAILURE);
    }
    printf("Starting %s %s (\"https://github.com/jcoignet/nmap\") at ", progname, VERSION_NBR);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", localtime(&tv.tv_sec));
    printf("%s CET\n", buf);
}

void	ft_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    struct tcphdr   *tcph;
//    struct iphdr    *iph;

//    iph = (struct iphdr*)(packet + sizeof(struct ether_header));
    tcph = (struct tcphdr*)(packet + sizeof(struct iphdr) + sizeof(struct ether_header));
    uint16_t	src_port, dst_port;
    t_answer *ans = (t_answer*)user;

    src_port = ntohs(tcph->source);//ntohs(tcph->source);
    dst_port = ntohs(tcph->dest);
    struct servent  *service = getservbyport(tcph->source, NULL);
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
    }

    if (tcph->syn == 1 && tcph->ack == 1)//check bitwise ?
	ans->status = OPEN;
    else if (tcph->ack == 1 && tcph->rst == 1)
	ans->status = CLOSED;
    (void)pkthdr;
    (void)packet;
}

t_answer	*ft_nmap(t_nmap *nmap)
{
    char	*dev, errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32	netp, maskp;
    pcap_t	*handle;
    struct bpf_program fp;	/* The compiled filter expression */
    char    *filter;
    int	    r;

    filter = ft_strjoin("src ", nmap->hostip);

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


    t_answer	*ans = malloc(sizeof(t_answer));
    ans->port = nmap->tport;
    ans->service = NULL;
    r= 0 ;
    ft_ping(nmap);

	r = pcap_dispatch(handle, 0, ft_callback, (u_char*)ans);
//	if (r == -1)
//	    fprintf(stderr, "port %d dispatch ret [%d] %s\n", nmap->tport, r, strerror(errno));
	if (r == 0)
	{
	    ans->status = FILTERED;
	    fprintf(stderr, "port %d filtered\n", nmap->tport);
	}

	return ans;
}

int	create_socket(t_nmap *nmap)
{
	int	sock;
	int	i = 1;
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	    return -1;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) < 0)
	    return -1;

	(void)nmap;
	return (sock);
}

int	main(int ac, char **av)
{
	t_nmap	*nmap;

	nmap = malloc(sizeof(t_nmap));
//	t_options *opt = parse_opt(ac, av);
//	print_options(opt);
	nmap->progname = ft_strdup(av[0]);
	nmap->hostname = ft_strdup(av[1]);
	nmap->tport = 22;//target port
	nmap->sport = 81;//our port
	addr_info(nmap);
	
	//create_sock depends of the port and scan type
	nmap->sock = create_socket(nmap);
	if (nmap->sock < 0)
	{
	    fprintf(stderr, "Socket creation failed %d [%s]\n", nmap->sock, strerror(errno));
	    return EXIT_FAILURE;
	}
	//nmap->info;

	t_answer *ans;
	while (nmap->tport < 31340)
	{
	    ans = ft_nmap(nmap);
	    printf("PORT %d STATUS %d SERVICE %s\n", ans->port, ans->status, ans->service);
	    if (nmap->tport == 22)
		nmap->tport = 25;
	    else if (nmap->tport == 25)
		nmap->tport = 80;
	    else if (nmap->tport == 80)
		nmap->tport = 9929;
	    else if (nmap->tport == 9929)
		nmap->tport = 31337;
	    else if (nmap->tport >= 31337)
		nmap->tport++;
	}
	(void)ac;
	return EXIT_SUCCESS;
}


