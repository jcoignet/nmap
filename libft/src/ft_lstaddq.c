/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstaddq.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/30 12:40:04 by gbersac           #+#    #+#             */
/*   Updated: 2015/07/29 15:57:22 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstaddq(t_list **alst, t_list *newe)
{
	t_list	*end;

	if (alst == NULL || newe == NULL)
		return ;
	if (*alst == NULL)
	{
		*alst = newe;
		return ;
	}
	end = ft_lst_last(*alst);
	end->next = newe;
	newe->prev = end;
}
