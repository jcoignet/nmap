/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:39 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/26 20:10:08 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int get_next_untested_port(t_nmap *nmap)
{
	static int buf = 0;
	return (buf++);
	(void)nmap;
}

void *test_port(void *v_nmap)
{
	t_nmap *nmap = (t_nmap*)v_nmap;
	int port = get_next_untested_port(nmap);
	printf("Test port: %d\n", port);
	pthread_exit((void*) nmap);
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
	nmap->opts = parse_opt(argc, argv);
	print_options(&nmap->opts);
	nmap->progname = ft_strdup(argv[0]);
	// nmap->hostname = ft_strdup(nmap->opts.);
	// addr_info(nmap);

	// Initialize and set thread detached attribute
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Launch threads
	threads = (pthread_t*)malloc(nmap->opts.nb_thread * sizeof(pthread_t));
	for (t = 0; t < nmap->opts.nb_thread ; t++) {
		printf("Main: creating thread %ld\n", t);
		rc = pthread_create(&threads[t], &attr, test_port, (void *)nmap);
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

	printf("end of prog\n");
	pthread_exit(NULL);
}
