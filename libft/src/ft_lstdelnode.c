/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdelnode.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/10 19:48:28 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:07:30 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	del_node(t_list *iter, void (*del)(t_list *))
{
	iter->prev->next = iter->next;
	iter->next->prev = iter->prev;
	del(iter);
}

void		ft_lstdelnode(t_list **lst, size_t n, void (*del)(t_list *))
{
	t_list	*iter;
	size_t	inode;

	iter = *lst;
	if (n == 0)
	{
		*lst = iter->next;
		del(iter);
		return ;
	}
	inode = 0;
	while (iter != NULL)
	{
		if (inode == n)
		{
			del_node(iter, del);
			return ;
		}
		iter = iter->next;
		++inode;
	}
}
