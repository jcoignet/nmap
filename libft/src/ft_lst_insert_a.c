/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_insert_a.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/24 21:35:27 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/24 22:19:09 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_lst_insert_a(t_list **lst, t_list *to_insert)
{
	if (lst == NULL || to_insert == NULL)
		return ;
	if (*lst == NULL)
	{
		*lst = to_insert;
		return ;
	}
	to_insert->next = (*lst)->next;
	to_insert->prev = (*lst);
	if ((*lst)->next != NULL)
		(*lst)->next->prev = to_insert;
	(*lst)->next = to_insert;
}
