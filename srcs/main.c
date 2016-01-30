/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:39 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/28 20:38:11 by gbersac          ###   ########.fr       */
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
				if (ip->ports[i].status == 0) {
					ip->ports[i].status = 1;
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

void set_port_as_tested(t_nmap *nmap, t_port *port, t_pstate *new_states)
{
	int i;
	i = 0;
	while (i < NB_SCAN)
	{
	    port->states[i] = new_states[i];
	    i++;
	}

	// test if all the ports has been tested
	i = 0;
	pthread_mutex_lock(&nmap->mutex);
	while (port->parent->ports[i].id != 0)
	{
		if (port->parent->ports[i].status == 0) {
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
	int			port_to_test;
	char		*ip_addr;
	t_port		*port;
	t_pstate	res[NB_SCAN];
	t_scan		scans[NB_SCAN];
	int		i;

	t_nmap *nmap = (t_nmap*)v_nmap;
	pthread_mutex_lock(&nmap->mutex);
	memcpy(scans, nmap->opts.scans, NB_SCAN * sizeof(t_scan));
	pthread_mutex_unlock(&nmap->mutex);

	port = get_next_untested_port(nmap, &port_to_test, &ip_addr);
	while (port != NULL) {
	    i = 0;
	    while (i < NB_SCAN)
	    {
		res[i] = STATE_UNTESTED;
		if (scans[i] == 1)
		    res[i] = test_one_port(port->id, ip_addr, *port->parent->info, i);
		i++;
	    }
	    //todo set_port_as_tested with res[nb_scan]
	    set_port_as_tested(nmap, port, (t_pstate*)res);
	    port = get_next_untested_port(nmap, &port_to_test, &ip_addr);
	}
	pthread_exit(NULL);
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


void	print_state_name(t_pstate state, int port)
{
    const char    *names[] = {
	"UNTESTED",
	"BEING_TESTED",
	"OPEN",
	"CLOSED",
	"FILTERED",
	"UNFILTERED",
	"OPEN|FILTERED"
    };

    printf("%s", names[state]);
    struct servent  *service = getservbyport(htons(port), NULL);//shouldnt be null but tcp or udp
    if (service != NULL)
    {
	printf(" %s/%s\n",
		service->s_name, service->s_proto);
    }
    else
	printf(" unknown\n");
}

pthread_mutex_t pcap_compile_mutex;
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

	pthread_mutex_init(&pcap_compile_mutex, NULL);

	// Initialize and set thread detached attribute
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Launch threads
	threads = (pthread_t*)malloc(nmap->opts.nb_thread * sizeof(pthread_t));
	for (t = 0; t < nmap->opts.nb_thread ; t++) {
//		printf("Main: creating thread %ld\n", t);
		rc = pthread_create(&threads[t], &attr, thread_fn, (void *)nmap);
		if (rc) {
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			exit(-1);
		}
	}

	// Free attribute and wait for the other threads
	pthread_attr_destroy(&attr);
	for (t = 0; t < nmap->opts.nb_thread ; t++) {
//		printf("try join %ld\n", (long)(threads[t]));
		rc = pthread_join(threads[t], &status);
		if (rc) {
			printf("ERROR; return code from pthread_join() is %d\n", rc);
			exit(-1);
		}
	}

	// all threads has been ended
	t_ip *fip = nmap->opts.ips->content;
	int i = 0;
	int it = 0;
	int filtered = 0;
	while (it < NB_SCAN)
	{
	    filtered = 0;
	    if (nmap->opts.scans[it] == 0)
	    {
		it++;
		continue ;
	    }
	    else
		printf("printing for scan %d\n", it);
	    while (fip->ports[i].id != 0) {
		if (fip->ports[i].states[it] != STATE_FILTERED)
		{
		    printf("port %d => ", fip->ports[i].id);
		    print_state_name(fip->ports[i].states[it], fip->ports[i].id);
		}
		else
		    filtered++;
		i++;
	    }
	    if (filtered > 0)
		    printf("Not shown: %d filtered ports.\n", filtered);
	    it++;
	}
	free_nmap(&nmap);
	printf("end of prog\n");
	pthread_mutex_destroy(&nmap->mutex);
	pthread_exit(NULL);
}
