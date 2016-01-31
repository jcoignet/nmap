#include "ft_nmap.h"

static void	print_scan_and_state(t_scan scan, t_pstate state)
{
    const char    *state_names[] = {
	"UNTESTED",
	"BEING_TESTED",
	"OPEN",
	"CLOSED",
	"FILTERED",
	"UNFILTERED",
	"OPEN|FILTERED"
    };
    const char    *scan_names[] = {
	"SYN",
	"NULL",
	"FIN",
	"XMAS",
	"ACK",
	"UDP"
    };
    printf("%s(%s) ", scan_names[scan], state_names[state]);
}

static void	display_port_data(t_port *port, t_options *opts)
{
    struct servent  *service;
    int	i = 0;

    printf("Port %d => ", port->id);
    while (i < NB_SCAN)
    {
	if (opts->scans[i] == 1)
	    print_scan_and_state(i, port->states[i]);
	i++;
    }
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
	ports = ((t_ip*)(ips->content))->ports;
	while (ports[i].id != 0)
	{
	    display_port_data(&(ports[i]), opts);
	    i++;
	}
	ips = ips->next;
    }
}