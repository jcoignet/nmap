/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:09 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/24 19:01:33 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <pcap.h>
# include <stdio.h>
# include <stdlib.h>
# include <netdb.h>
# include <string.h>
# include <arpa/inet.h>
# include <netinet/ether.h>
# include <netinet/ip.h>
# include <sys/time.h>
# include <time.h>
# include <errno.h>
# include <stdint.h>

#include "libft.h"

# define IP_BUFFLEN 512
# define VERSION_NBR "1.0"
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

typedef struct    s_nmap
{
    char	    *progname;
}		    t_nmap;

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

t_options		*parse_opt(int ac, char **av);
void			print_options(t_options *opt);

#endif
