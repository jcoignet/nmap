/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_clstadd.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/02 21:37:48 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/02 22:34:37 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_clstadd(t_list **alst, t_list *newe)
{
	t_list	*buffer;

	if (*alst == NULL)
	{
		*alst = newe;
		newe->next = newe;
		newe->prev = newe;
		return ;
	}
	buffer = (*alst)->next;
	(*alst)->next = newe;
	buffer->prev = newe;
	newe->prev = (*alst);
	newe->next = buffer;
}
