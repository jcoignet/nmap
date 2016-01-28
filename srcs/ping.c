#include "ft_nmap.h"

u_short		ft_checksum(u_short *data, int len)
{
	int				i;
	unsigned int	sum;
	u_short	checksum;
	ushort			*ptr;

	sum = 0;
	ptr = data;
	i = len;
	while (i > 1)
	{
		sum += *ptr;
		ptr += 1;
		i -= 2;
	}
	if (i == 1)
		sum += *((u_char*)ptr);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum += (sum >> 16);
	checksum = ~sum;
	return (checksum);
}

// void		ft_catch(t_nmap *nmap)
// {
// 	char			recvbuf[IP_MAXPACKET];
// 	int				recv_len;

// 	if ((recv_len = recvfrom(nmap->sock, (void*)recvbuf, sizeof(recvbuf), 0, NULL, 0)) < 0)
// 	{
// 		if (errno != EAGAIN)
// 			dprintf(2, "Error: recvmsg failed.\n");
// 		return ;
// 	}
// 	printf("reclen %d\n", recv_len);
// 	struct tcphdr *tcph = (struct tcphdr*)(recvbuf + sizeof(struct iphdr));
//     uint16_t	src_port, dst_port;
//     uint16_t	src_p, dst_p;

//     src_port = ntohs(tcph->source);//ntohs(tcph->source);
//     dst_port = ntohs(tcph->dest);
//     src_p = tcph->source;
//     dst_p = tcph->dest;
//     printf("CATCH src %d or %d dst %d or %d SYN %d ACK %d RST %d\n",
// 	    src_port, src_p, dst_port, dst_p, tcph->syn, tcph->ack, tcph->rst);
// }

struct pseudo_header
{
        u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t length;
};

void	    udp_ping(t_port *port, int sock, char *ip_addr)
{
    char	sendbuf[sizeof(struct udphdr)];
    int	len;
    int	sent;
    struct udphdr *udph;
    struct sockaddr_in sin;

    len = sizeof(struct udphdr);
    bzero(sendbuf, IP_MAXPACKET);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port->id);
    sin.sin_addr.s_addr = inet_addr(ip_addr);
    udph = (struct udphdr*)sendbuf;
    udph->source = htons(port->src_port);
    udph->dest = htons (port->id);
    udph->len = htons(8);
    udph->check = 0; //leave checksum 0 now, filled later by pseudo header

    struct pseudo_header psh;
    psh.source_address = inet_addr("192.168.0.8");
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.length = htons(sizeof(struct udphdr));
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr));
    udph->check = ft_checksum((u_short*) pseudogram , psize);
    if ((sent = sendto(sock, sendbuf, len, 0,
			port->parent->info->ai_addr, port->parent->info->ai_addrlen)) < 0)
	printf("Error: sendto failed.\n");
    if (sent != len)
	printf("Warning: sent %d expected %d\n", sent, len);
}

void		ft_ping(t_port *port, int sock, char *ip_addr, t_scan scan)
{
	if (scan == SCAN_UDP)
	{
	    udp_ping(port, sock, ip_addr);
	    return ;
	}

	char	sendbuf[sizeof(struct tcphdr)];
	int	len;
	int	sent;
	struct tcphdr *tcph;
	struct sockaddr_in sin;

	len = sizeof(struct tcphdr);
	bzero(sendbuf, len);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port->id);
	sin.sin_addr.s_addr = inet_addr(ip_addr);
	tcph = (struct tcphdr*)sendbuf;

	tcph->source = htons(port->src_port);//src port
	tcph->dest = htons(port->id);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->res1 = 0;
	tcph->urg = 0;
	tcph->ack = 0;
	tcph->psh = 0;
	tcph->rst = 0;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tcph->check = 0;

	struct pseudo_header psh;
	psh.source_address = inet_addr("192.168.0.8");
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.length = htons(sizeof(struct tcphdr));
	int psize  = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char	*pseudogram = malloc(psize);
	ft_memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	ft_memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
	tcph->check = ft_checksum((u_short*)pseudogram, psize);
	if ((sent = sendto(sock, sendbuf, len, 0,
			port->parent->info->ai_addr, port->parent->info->ai_addrlen)) < 0)
		printf("Error: sendto failed.\n");
	if (sent != len)
		printf("Warning: sent %d expected %d\n", sent, len);
}

