/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:09 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/24 18:43:20 by gbersac          ###   ########.fr       */
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

# define IP_BUFFLEN 512
# define VERSION_NBR "1.0"

typedef struct    s_nmap
{
    char	    *progname;
}		    t_nmap;

#endif
