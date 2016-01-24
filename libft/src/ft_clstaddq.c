/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_clstaddq.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/02 21:37:48 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/02 23:12:44 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_clstaddq(t_list **alst, t_list *newe)
{
	t_list	*buffer;

	if (*alst == NULL)
	{
		*alst = newe;
		newe->next = newe;
		newe->prev = newe;
		return ;
	}
	buffer = (*alst)->prev;
	(*alst)->prev = newe;
	buffer->next = newe;
	newe->prev = buffer;
	newe->next = *alst;
}
