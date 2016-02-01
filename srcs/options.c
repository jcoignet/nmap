/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/24 17:22:23 by gbersac           #+#    #+#             */
/*   Updated: 2016/01/27 17:48:10 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void print_options(t_options *opt)
{
	printf("Ips: ");
	t_list *iter = opt->ips;
	while (iter != NULL)
	{
		printf("%s ", ((t_ip*)iter->content)->hostname);
		iter = iter->next;
	}
	printf("\nports: %s\n", opt->ports);
	printf("nb_thread: %d\n", opt->nb_thread);
	printf("timeout: %d\n", opt->timeout);

	printf("Scans: ");
	if (opt->scans[SCAN_SYN] == 1)
		printf("SYN ");
	if (opt->scans[SCAN_NULL] == 1)
		printf("NULL ");
	if (opt->scans[SCAN_FIN] == 1)
		printf("FIN ");
	if (opt->scans[SCAN_XMAS] == 1)
		printf("XMAS ");
	if (opt->scans[SCAN_ACK] == 1)
		printf("ACK ");
	if (opt->scans[SCAN_UDP] == 1)
		printf("UDP ");
	if (opt->scans[SCAN_WIN] == 1)
		printf("WIN ");
	printf("\n");
}

void free_options(t_options *opt)
{
	ft_lstdel(&opt->ips, free);
	free(opt->ports);
}

static void help(t_options *opt)
{
	free_options(opt);
	puts("Help Screen\n"
"ft_nmap [OPTIONS]\n"
"--help      Print this help screen\n"
"--ports     ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n"
"--ip        ip addresses to scan in dot format\n"
"--file      File name containing IP addresses to scan,\n"
"--speedup   [250 max] number of parallel threads to use\n"
"--scan      SYN/NULL/FIN/XMAS/ACK/UDP\n");
	exit(EXIT_FAILURE);
}

static int update_ports(t_options *opt, char *av)
{
	if (av == NULL || av[0] == '-')
		return (-1);
	opt->ports = strdup(av);
	return (2);
}

static int update_timeout(t_options *opt, char *av)
{
	if (av == NULL || av[0] == '-')
		return (-1);
	opt->timeout = atoi(av);
	if (opt->timeout <= 0)
		opt->timeout = PCAP_TIMEOUT;
	return (2);
}

static int update_nb_thread(t_options *opt, char *av)
{
	if (av == NULL || av[0] == '-')
		return (-1);
	opt->nb_thread = atoi(av);
	if (opt->nb_thread <= 0)
		opt->nb_thread = 1;
	if (opt->nb_thread > 255)
		opt->nb_thread = 255;
	return (2);
}

static void add_one_ip(t_options *opt, char *ip)
{
	t_ip	*new_ip;

	new_ip = (t_ip*)malloc(sizeof(t_ip));
	bzero(new_ip, sizeof(t_ip));
	new_ip->hostname = strdup(ip);
	ft_push_back(&opt->ips, new_ip, sizeof(t_ip));
}

static int update_ips(t_options *opt, char **av)
{
	int		to_return;

	if (av[1] == NULL || av[1][0] == '-')
		return (-1);
	to_return = 1;
	while (av[to_return] != NULL && av[to_return][0] != '-')
	{
		add_one_ip(opt, av[to_return]);
		++to_return;
	}
	return (to_return);
}

static int update_ip_file(t_options *opt, char *av)
{
	if (av == NULL || av[0] == '-')
		return (-1);
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen(av, "r");
	if (fp == NULL)
		exit(EXIT_FAILURE);

	while ((read = getline(&line, &len, fp)) != -1) {
		if (!ft_strequ(line, ""))
			add_one_ip(opt, line);
	}

	fclose(fp);
	if (line)
		free(line);
	return (2);
}

static int update_scan(t_options *opt, char **av)
{
	int		to_return;

	if (av[1] == NULL || av[1][0] == '-')
		return (-1);
	to_return = 1;
	bzero(opt->scans, NB_SCAN * sizeof(t_scan));
	while (av[to_return] != NULL && av[to_return][0] != '-')
	{
		if (ft_strequ(av[to_return], "SYN"))
			opt->scans[SCAN_SYN] = 1;
		if (ft_strequ(av[to_return], "NULL"))
			opt->scans[SCAN_NULL] = 1;
		if (ft_strequ(av[to_return], "FIN"))
			opt->scans[SCAN_FIN] = 1;
		if (ft_strequ(av[to_return], "XMAS"))
			opt->scans[SCAN_XMAS] = 1;
		if (ft_strequ(av[to_return], "ACK"))
			opt->scans[SCAN_ACK] = 1;
		if (ft_strequ(av[to_return], "UDP"))
			opt->scans[SCAN_UDP] = 1;
		if (ft_strequ(av[to_return], "WIN"))
			opt->scans[SCAN_WIN] = 1;
		++to_return;
	}
	return (to_return);
}

static int test_arg(t_options *opt, char **av)
{
	int		i;

	i = 0;
	if (ft_strequ(av[0], "--help"))
		help(opt);
	else if (ft_strequ(av[0], "--ports"))
		i = update_ports(opt, av[1]);
	else if (ft_strequ(av[0], "--ip"))
		i = update_ips(opt, av);
	else if (ft_strequ(av[0], "--file"))
		i = update_ip_file(opt, av[1]);
	else if (ft_strequ(av[0], "--speedup"))
		i = update_nb_thread(opt, av[1]);
	else if (ft_strequ(av[0], "--timeout"))
		i = update_timeout(opt, av[1]);
	else if (ft_strequ(av[0], "--scan"))
		i = update_scan(opt, av);
	else
		help(opt);
	return (i);
}

void test_opt(t_options *opt)
{
	if (opt->ips == NULL)
		help(opt);
	if (opt->nb_thread < 1)
		opt->nb_thread = 1;
	if (opt->ports == NULL)
		opt->ports = strdup("1-1024");
	if (opt->timeout <= 0)
		opt->timeout = PCAP_TIMEOUT;
}

t_options parse_opt(int ac, char **av)
{
	t_options	to_return;
	int			i;
	int			res;

	bzero(&to_return, sizeof(t_options));
	to_return.scans[SCAN_SYN] = 1;
	to_return.scans[SCAN_NULL] = 1;
	to_return.scans[SCAN_FIN] = 1;
	to_return.scans[SCAN_XMAS] = 1;
	to_return.scans[SCAN_ACK] = 1;
	to_return.scans[SCAN_UDP] = 1;
	to_return.scans[SCAN_WIN] = 0;
	to_return.timeout = PCAP_TIMEOUT;

	i = 1;
	while (av[i] != NULL)
	{
		res = test_arg(&to_return, av + i);
		if (res == -1)
			_exit(EXIT_FAILURE);
		i += res;
	}

	test_opt(&to_return);
	return (to_return);
	(void)ac;
}
