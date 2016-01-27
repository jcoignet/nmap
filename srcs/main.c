/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:39 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/27 17:47:44 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void free_nmap(t_nmap **nmap)
{
	free_options(&(*nmap)->opts);
	//TODO free other options
	pthread_mutex_destroy(&(*nmap)->mutex);
	free(*nmap);
	nmap = NULL;
}

// void display_ip_header()
// {
//	struct hostent		*client;
//	 char			*fqdn;
// 	((struct sockaddr_in*)(nmap->info->ai_addr))->sin_port = nmap->tport;
// 	client = gethostbyaddr((void*)&(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr),
// 		sizeof(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr), AF_INET);
// 	if (client == NULL || client->h_name == NULL)
// 	    fqdn = strdup(nmap->hostname);
// 	else
// 	    fqdn = strdup(client->h_name);
// 	printf("ft_nmap scan report for %s (%s)\n", nmap->hostname, buf);
// 	//host is up + ping
// 	printf("rDNS record for %s: %s\n\n", buf, fqdn);
// }

void quit(t_nmap *nmap, int quit_status)
{
	free_nmap(&nmap);
	exit(quit_status);
}

t_port *get_next_untested_port(t_nmap *nmap, int *port, char **ip_addr)
{
	t_list	*iter;
	t_ip	*ip;
	int		i;

	//for each ip
	iter = nmap->opts.ips;
	pthread_mutex_lock(&nmap->mutex);
	while (iter != NULL)
	{
		ip = (t_ip*)iter->content;
		if (!ip->tested) {

			// for each port to test of this ip
			i = 0;
			while (ip->ports[i].id != 0) {

				// return the untested port
				if (ip->ports[i].state == STATE_UNTESTED) {
					ip->ports[i].state = STATE_BEING_TESTED;
					*port = ip->ports[i].id;
					*ip_addr = ip->hostip;
					pthread_mutex_unlock(&nmap->mutex);
					return (&ip->ports[i]);
				}
				++i;
			}
		}
		iter = iter->next;
	}
	pthread_mutex_unlock(&nmap->mutex);
	return (NULL);
}

void set_port_as_tested(t_nmap *nmap, t_port *port, t_pstate new_state)
{
	port->state = new_state;

	// test if all the ports has been tested
	int i;
	i = 0;
	pthread_mutex_lock(&nmap->mutex);
	while (port->parent->ports[i].id != 0)
	{
		if (port->parent->ports[i].state == STATE_UNTESTED) {
			port->parent->tested = 0;
			pthread_mutex_unlock(&nmap->mutex);
			return ;
		}
		++i;
	}
	port->parent->tested = 1;
	pthread_mutex_unlock(&nmap->mutex);
}

void *thread_fn(void *v_nmap)
{
	int		port_to_test;
	char	*ip_addr;
	t_port	*port;

	t_nmap *nmap = (t_nmap*)v_nmap;
	port = get_next_untested_port(nmap, &port_to_test, &ip_addr);
	while (port != NULL) {
	    if (nmap->opts.scans[SCAN_UDP] == 1)//TMP
		test_one_port(nmap, port, ip_addr, SCAN_UDP);
	    else
		test_one_port(nmap, port, ip_addr, SCAN_SYN);

	    port = get_next_untested_port(nmap, &port_to_test, &ip_addr);
	}
	pthread_exit((void*) nmap);
}

void addr_info(t_ip *ip)
{
	struct addrinfo		*info;
	char			buf[IP_BUFFLEN];

	if (getaddrinfo(ip->hostname, NULL, NULL, &info) != 0)
	{
		fprintf(stderr, "ft_nmap: unknown host %s\n", ip->hostname);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET,
			(void*)&(((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr),
			buf,IP_BUFFLEN);
	ip->hostip = strdup(buf);
	ip->info = info;
}

static void add_addr_info(t_nmap *nmap)
{
	t_list *iter = nmap->opts.ips;
	while (iter != NULL)
	{
		addr_info(iter->content);
		iter = iter->next;
	}
}


int main (int argc, char *argv[])
{
	pthread_t *threads;
	pthread_attr_t attr;
	int rc;
	long t;
	void *status;
	t_nmap	*nmap;

	// Initialize nmap
	nmap = malloc(sizeof(t_nmap));
	nmap->sport = 80;
	nmap->opts = parse_opt(argc, argv);
	parse_ports(nmap);
	print_options(&nmap->opts);
	nmap->progname = ft_strdup(argv[0]);
	pthread_mutex_init(&nmap->mutex, NULL);
	add_addr_info(nmap);
	// nmap->hostname = ft_strdup(nmap->opts.);
	// addr_info(nmap);

	// Initialize and set thread detached attribute
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Launch threads
	threads = (pthread_t*)malloc(nmap->opts.nb_thread * sizeof(pthread_t));
	for (t = 0; t < nmap->opts.nb_thread ; t++) {
		printf("Main: creating thread %ld\n", t);
		rc = pthread_create(&threads[t], &attr, thread_fn, (void *)nmap);
		if (rc) {
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			exit(-1);
		}
	}

	// Free attribute and wait for the other threads
	pthread_attr_destroy(&attr);
	for (t = 0; t < nmap->opts.nb_thread ; t++) {
		rc = pthread_join(threads[t], &status);
		if (rc) {
			printf("ERROR; return code from pthread_join() is %d\n", rc);
			exit(-1);
		}
		printf("Main: completed join with thread %ld having a status of %ld\n",t,(long)status);
	}
	
	// all threads has been ended
	t_ip *fip = nmap->opts.ips->content;
	int i = 0;
	while (fip->ports[i].id != 0) {
	    printf("port %d => %d\n", fip->ports[i].id, fip->ports[i].state);
	    i++;
	}
	free_nmap(&nmap);
	printf("end of prog\n");
	pthread_mutex_destroy(&nmap->mutex);
	pthread_exit(NULL);
}
