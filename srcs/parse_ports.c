/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_ports.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/27 12:11:50 by gbersac           #+#    #+#             */
/*   Updated: 2016/01/27 16:11:37 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
** Ports set is for "1-3" string
*/
void port_format_error(t_nmap *nmap)
{
		fprintf(stderr, "Error for port format: \"begin-end\" or \"p1[,pn]*\"\n");
		quit(nmap, EXIT_FAILURE);
}

static void set_port_id(t_port *port, int id, int index)
{
	if (id <= 0)
		return ;
	port[index].id = id;
}

static t_port *ports_set(t_nmap *nmap, char *ports_str, int *ttl_port)
{
	t_port	*ports_array;
	int		begin, end, ret;

	// analyze ports_str
	ret = sscanf(ports_str, "%d-%d", &begin, &end);
	if (ret != 2 || begin > end)
		port_format_error(nmap);
	ports_array = (t_port*)malloc((end - begin + 1) * sizeof(t_port));

	// init ports
	bzero(ports_array, (end - begin + 1) * sizeof(t_port));
	int i;
	for (i = 0 ; i < (end - begin) ; ++i) {
		set_port_id(ports_array, begin + i, i);
	}

	*ttl_port = i;
	return (ports_array);
}

/*
** Ports list is for "1,2,3" string
*/
static t_port *ports_list(t_nmap *nmap, const char *ports_str, int *ttl_port)
{
	t_port	*ports_array = NULL;
	int		port_id, ret, nb_port;

	// calculate number of ports
	nb_port = 1;
	int i = 0;
	while (ports_str[i] != '\0') {
		if (ports_str[i] == ',')
			++nb_port;
		++i;
	}

	// init ports_array
	ports_array = (t_port*)malloc((nb_port + 1) * sizeof(t_port));
	bzero(ports_array, (nb_port + 1) * sizeof(t_port));

	// first port
	ret = sscanf(ports_str, "%d", &port_id);
	if (ret != 1)
		port_format_error(nmap);
	set_port_id(ports_array, port_id, 0);

	// following ports
	i = 1;
	while (ret > 0) {
		while (*ports_str != '\0' && *ports_str != ',')
			++ports_str;
		ret = sscanf(ports_str, ",%d", &port_id);
		if (ret > 0)
		{
			++ports_str;
			set_port_id(ports_array, port_id, i);
			ports_array[i].id = port_id;
		}
		++i;
	}

	*ttl_port = nb_port;
	return (ports_array);
}

void print_ports(const t_port *ports)
{
	int		i;

	i = 0;
	while (ports[i].id != 0)
	{
		printf("%d ", ports[i].id);
		++i;
	}
	printf("\n");
}

void parse_ports(t_nmap *nmap)
{
	char	*ports_str;
	t_port	*ports_array; // end with a null (ports == 0)
	int		nb_port;

	// get the ports to test for each ip address
	ports_str = nmap->opts.ports;
	if (strstr(ports_str, "-"))
		ports_array = ports_set(nmap, ports_str, &nb_port);
	else
		ports_array = ports_list(nmap, ports_str, &nb_port);

	// add ports copy to all
	t_list *iter = nmap->opts.ips;
	while (iter != NULL) {
		t_ip *ip = (t_ip*)iter->content;
		ip->ports = (t_port*)malloc((nb_port + 1) * sizeof(t_port));
		memcpy(ip->ports, ports_array, (nb_port + 1) * sizeof(t_port));

		// set this ip as parent of those ports
		int i = 0;
		while (ip->ports[i].id != 0) {
			ip->ports[i].parent = ip;
			++i;
		}
		iter = iter->next;
	}
}
