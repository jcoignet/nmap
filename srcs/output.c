#include "ft_nmap.h"

static void display_ip_info(t_ip *ip)
{
	struct hostent		*client;
	 char			*fqdn;

	client = gethostbyaddr((void*)&(((struct sockaddr_in*)(ip->info->ai_addr))->sin_addr.s_addr),
		sizeof(((struct sockaddr_in*)(ip->info->ai_addr))->sin_addr.s_addr), AF_INET);
	if (client == NULL || client->h_name == NULL)
	    fqdn = strdup(ip->hostname);
	else
	    fqdn = strdup(client->h_name);
	printf("\nft_nmap scan report for %s (%s)\n", ip->hostname, ip->hostip);
	//host is up + ping
	printf("rDNS record for %s: %s\n", ip->hostip, fqdn);
	free(fqdn);
}

static void	print_scan_and_state(t_scan scan, t_pstate state, int isccl)
{
    const char    *state_names[] = {
	"UNTESTED",
	"BEING_TESTED",
	"OPEN",
	"CLOSED",
	"UNFILTERED",
	"FILTERED",
	"OPEN|FILTERED"
    };
    const char    *scan_names[] = {
	"SYN",
	"NULL",
	"FIN",
	"XMAS",
	"ACK",
	"UDP",
	"WIN"
    };
    if (isccl == 0)
        printf("%s(%s) ", scan_names[scan], state_names[state]);
    else
	printf("Conclusion %s ", state_names[state]);
}

static void	display_port_data(t_port *port, t_options *opts)
{
    struct servent  *service;
    int	i = 0;
    unsigned int ccl = STATE_OPENFILTERED;

    printf("Port %d => ", port->id);
    while (i < NB_SCAN)
    {
	if (opts->scans[i] == 1)
	{
	    print_scan_and_state(i, port->states[i], 0);
	    if (port->states[i] < ccl)
		ccl = port->states[i];
	}
	i++;
    }
    /* print conclusion
     * open > closed > unfiltered > filtered > open|filtered
     */
   if (ccl < STATE_OPEN)
	ccl = STATE_FILTERED;
    print_scan_and_state(0, ccl, 1);
    service = getservbyport(htons(port->id), NULL);
    if (service != NULL)
	printf("Service: %s.\n", service->s_name);
    else
	printf("Service: unknown.\n");
}

void	output_scan(t_options *opts)
{
    t_list  *ips = opts->ips;
    t_port  *ports;
    int	    i;

    while (ips != NULL)
    {
	i = 0;
	display_ip_info((t_ip*)ips->content);
	ports = ((t_ip*)(ips->content))->ports;
	while (ports[i].id != 0)
	{
	    display_port_data(&(ports[i]), opts);
	    i++;
	}
	ips = ips->next;
    }
}