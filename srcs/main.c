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

void		addr_info(char *hostname)
{
	struct addrinfo		*info;
	char			buf[IP_BUFFLEN];
	struct hostent		*client;
	char			*fqdn;

	if (getaddrinfo(hostname, NULL, NULL, &info) != 0)
	{
		fprintf(stderr, "ft_nmap: unknown host %s\n", hostname);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET,
			(void*)&(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr),
			buf,IP_BUFFLEN);
//	ping_data->hostip = ft_strdup(buf);
//	ping_data->info = info;
	client = gethostbyaddr((void*)&(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr),
		sizeof(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr), AF_INET);
	if (client == NULL || client->h_name == NULL)
	    fqdn = strdup(hostname);
	else
	    fqdn = strdup(client->h_name);
	printf("ft_nmap scan report for %s (%s)\n", hostname, buf);
	//host is up + ping
	printf("rDNS record for %s: %s\n", buf, fqdn);
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

u_char* handle_ip(const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    unsigned int len;

    /* jump pass the ethernet header */
    ip = (struct ip*)(packet + sizeof(struct ether_header));
    length = pkthdr->len - sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
   if (length < sizeof(struct ip))
   {
        printf("truncated ip %d",length);
        return NULL;
   }

   len     = ntohs(ip->ip_len);
   hlen = ip->ip_hl;
   version = ip->ip_v;
   /* check version */
   if(version != 4)
   {
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
   }

    /* check header length */
    if(hlen < 5 )
        fprintf(stdout,"bad-hlen %d \n",hlen);

   /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout,"IP: ");
        fprintf(stdout,"src %s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout,"dst %s hlen %d version %d len %d offset %d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
    }

        return NULL;
}

u_int16_t handle_ethernet(const u_char* packet)
{
    struct ether_header *eptr;  /* net/ethernet.h */

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    fprintf(stdout,"ethernet header source: %s",
            ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    fprintf(stdout," destination: %s ",
            ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    	fprintf(stdout,"(IP)");
    else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
        fprintf(stdout,"(ARP)");
    else if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
        fprintf(stdout,"(RARP)");
    else
        fprintf(stdout,"(?)");
    fprintf(stdout,"\n");

    return eptr->ether_type;
}

void	ft_callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    if (user == NULL)
    	(void)user;
    if (pkthdr == NULL)
	   printf("pkthdr null\n");
    if (packet == NULL)
    	printf("packet null\n");
    u_int16_t type = handle_ethernet(packet);
    if (type == 8)//ip
    	handle_ip(pkthdr, packet);
    printf("TYPE%d\n", type);
}

void	ft_nmap(void)
{
    char	*dev, errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32	netp, maskp;
    pcap_t	*handle;
    struct bpf_program fp;	/* The compiled filter expression */
    char filter_exp[] = "ip dst 216.58.211.67";	/* The filter expression */
//    char filter_exp[] = "(ip dst 216.58.211.67) and (dst port 80)";

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	printf("Device: %s\n", dev);
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

    if (pcap_compile(handle, &fp, filter_exp, 0, netp) == -1)
    {
    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    	exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
    	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    	exit(EXIT_FAILURE);
    }

    //cnt = nbr of packets if 0 all
    while(1)
    {
    	int r = pcap_dispatch(handle, 0, ft_callback, NULL);
    	fprintf(stderr, "dispatch ret [%d] %s\n", r, strerror(errno));
    }
}

int	main(int ac, char **av)
{

/*	printf("netp%d mask%d\n", netp, maskp);
	struct in_addr tmp;
	tmp.s_addr=netp;
	printf ("%s\n", inet_ntoa(tmp));
	nmap_header(av[0]);
	addr_info("google.fr");//216.58.211.67*/
    t_options *opt = parse_opt(ac, av);
    print_options(opt);
	ft_nmap();
	return EXIT_SUCCESS;
}
