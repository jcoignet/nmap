/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_slstaddq.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/19 01:57:01 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/19 02:01:54 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_slstaddq(t_list **lst, char *str)
{
	t_list	*end;
	t_list	*newe;

	if (lst == NULL || str == NULL)
		return ;
	newe = ft_lstnew(NULL, 0);
	newe->content = str;
	if (*lst == NULL)
	{
		*lst = newe;
		return ;
	}
	end = ft_lst_last(*lst);
	end->next = newe;
	newe->prev = end;
}
