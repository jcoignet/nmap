/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcoignet <jcoignet@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:09 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/22 13:02:32 by jcoignet         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <pcap.h>
# include <stdio.h>
# include <stdlib.h>
# include <netdb.h>
# include <string.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netinet/ether.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <time.h>
# include <errno.h>

# define IP_BUFFLEN 512
# define VERSION_NBR "1.0"
# define PING_DATALEN 56
# define ICMP_HEADER_LEN 8

typedef struct	s_nmap
{
    int		    sock;
    char	    *progname;
    char	    *hostname;
    char	*hostip;
    struct addrinfo	*info;
}		t_nmap;

void		ft_ping(t_nmap *nmap);

#endif