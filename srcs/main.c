/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcoignet <jcoignet@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/22 12:54:39 by jcoignet          #+#    #+#             */
/*   Updated: 2016/01/22 13:01:57 by jcoignet         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	main(void)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(EXIT_FAILURE);
	}
	printf("Device: %s\n", dev);
	return EXIT_SUCCESS;
}