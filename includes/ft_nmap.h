/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:09 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/28 20:37:16 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

#define _GNU_SOURCE

# include <pcap.h>
# include <stdio.h>
# include <stdlib.h>
# include <netdb.h>
# include <string.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
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
# define SRC_PORT 80
# define PCAP_TIMEOUT 3000

pthread_mutex_t pcap_compile_mutex;

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
	STATE_UNTESTED = 0,
	STATE_BEING_TESTED,
	STATE_OPEN,
	STATE_CLOSED,
	STATE_FILTERED,
	STATE_UNFILTERED,
	STATE_OPENFILTERED
}				t_pstate;

struct s_ip;

typedef struct	s_callback_data
{
    t_pstate	state;
    t_scan	scan;
}		t_callback_data;

typedef struct	s_port
{
	int			id;
	int			status;
	int			src_port;
	t_pstate	states[NB_SCAN];
	struct s_ip	*parent;
}				t_port;

typedef struct	s_ip
{
	char		*hostname;
	char		*hostip;
	t_port		*ports;

	/*
	** true if all ports of this ip has been tested.
	*/
	int			tested;
    struct addrinfo	*info;
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
    char	    	*progname;
    t_options		opts;
    pthread_mutex_t	mutex;
    int		    	sport;
}				t_nmap;

t_options		parse_opt(int ac, char **av);
void			print_options(t_options *opt);
void			ft_ping(int port, int sock, char *ip_addr, t_scan scan,
						struct addrinfo info);
void			parse_ports(t_nmap *nmap);
void			quit(t_nmap *nmap, int quit_status);
void			free_options(t_options *opt);
t_pstate 		test_one_port(int port, char *ip_addr,
								struct addrinfo addrinfo, t_scan scan);
void			set_port_as_tested(t_nmap *nmap, t_port *port, t_pstate *new_states);

/*
** Return the next port to test.
**
** port:	the value of this pointer will be set to the port to test.
** ip_addr:	the value of this pointer will be set to the ip address to test.
**
** return:	NULL if all ports has been tested. A pointer to the port to test
** 			otherwise.
*/
t_port			 *get_next_untested_port(t_nmap *nmap,
											int *port, char **ip_addr);

#endif
