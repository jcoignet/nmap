/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_rotate.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/27 16:20:53 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/02 21:48:35 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	recursive_rotate(t_list *first, t_list *last)
{
	t_list	*buffer;

	if (first != last && first->next != last)
		recursive_rotate(first->next, last->prev);
	buffer = first->next;
	first->next = first->prev;
	first->prev = buffer;
	if (first != last)
	{
		buffer = last->next;
		last->next = last->prev;
		last->prev = buffer;
	}
}

void		ft_lst_rotate(t_list **lst)
{
	t_list	*new_first;

	if (*lst == NULL)
		return ;
	new_first = ft_lst_last(*lst);
	recursive_rotate(*lst, new_first);
	*lst = new_first;
}
