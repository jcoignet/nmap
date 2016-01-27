/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:09 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/27 14:02:07 by gbersac          ###   ########.fr       */
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
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <time.h>
# include <errno.h>
# include <stdint.h>
# include <pthread.h>
# include <math.h>

#ifdef __APPLE__
# include <netinet/if_ether.h>
#elif __linux__
# include <netinet/ether.h>
#endif

#include "libft.h"

# define IP_BUFFLEN 512
# define VERSION_NBR "1.0"
# define PING_DATALEN 56
# define ICMP_HEADER_LEN 8
# define NB_SCAN 6

typedef enum	e_scan
{
	SCAN_SYN,
	SCAN_NULL,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_ACK,
	SCAN_UDP
}				t_scan;

typedef enum	e_pstate
{
	STATE_UNTESTED,
	STATE_OPEN,
	STATE_CLOSE,
	STATE_FILTERING,
	STATE_UNFILTERED
}				t_pstate;

typedef struct	s_port
{
	int			id;
	t_pstate	state;
}				t_port;

typedef struct	s_ip
{
	char		*str;
	t_port		*ports;

	/*
	** true if all ports of this ip has been tested.
	*/
	int			tested;
}				t_ip;

typedef struct	s_options
{
	char		*ports;
	t_list		*ips;
	int			nb_thread;

	/*
	** if (opt->scans[SCAN_UDP] == 1), then scan udp is required.
	*/
	t_scan		scans[NB_SCAN];
}				t_options;

typedef struct	s_nmap
{
    int		    	sock;
    char	    	*progname;
    char	    	*hostname;
    char			*hostip;
    struct addrinfo	*info;
    t_options		opts;
}		t_nmap;

t_options		parse_opt(int ac, char **av);
void			print_options(t_options *opt);
void			ft_ping(t_nmap *nmap);
void			parse_ports(t_nmap *nmap);
void			quit(t_nmap *nmap, int quit_status);
void			free_options(t_options *opt);

#endif
