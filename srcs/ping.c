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

void		ft_catch(t_nmap *nmap)
{
	char			recvbuf[IP_MAXPACKET];
	int				recv_len;

	if ((recv_len = recvfrom(nmap->sock, (void*)recvbuf, sizeof(recvbuf), 0, NULL, 0)) < 0)
	{
		if (errno != EAGAIN)
			dprintf(2, "Error: recvmsg failed.\n");
		return ;
	}
	printf("reclen %d\n", recv_len);
}

void		ft_ping(t_nmap *nmap)
{
	char	sendbuf[IP_MAXPACKET];
	struct icmp	*icmp;
	int	len;
	int	sent;
//	static int seq = 1;
//	struct timeval	start;

//	ping_data->nb_sent++;
	icmp = (struct icmp*)sendbuf;
	icmp->icmp_code = 0;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = 1;
//	icmp->icmp_seq = seq;
	icmp->icmp_id = getpid();
	icmp->icmp_cksum = ft_checksum((u_short*)icmp, sizeof(struct icmp));
	len = PING_DATALEN + ICMP_HEADER_LEN;
//	gettimeofday(&start, NULL);
//	add_start_time(&start, ping_data, seq);
//	seq++;
	if ((sent = sendto(nmap->sock, sendbuf, len, 0,
			nmap->info->ai_addr, nmap->info->ai_addrlen)) < 0)
	{
		printf("Error: sendto failed.\n");
		exit(EXIT_FAILURE);
	}
	if (sent != len)
		printf("Warning: sent %d expected %d\n", sent, len);
	ft_catch(nmap);
}

