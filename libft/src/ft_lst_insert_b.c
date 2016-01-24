/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_insert_b.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/24 17:37:58 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/24 17:43:26 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_lst_insert_b(t_list **lst, t_list *to_insert)
{
	if (lst == NULL || to_insert == NULL)
		return ;
	if (*lst == NULL)
	{
		*lst = to_insert;
		return ;
	}
	to_insert->prev = (*lst)->prev;
	to_insert->next = (*lst);
	if ((*lst)->prev != NULL)
		(*lst)->prev->next = to_insert;
	(*lst)->prev = to_insert;
}
