/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdel.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 10:42:14 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/06 15:48:00 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_lstdel(t_list **alst, void (*del)(void *))
{
	t_list	*node;
	t_list	*next;

	if (alst == NULL || del == NULL)
		return ;
	node = *alst;
	while (node != NULL)
	{
		next = node->next;
		ft_lstdelone(&node, del);
		node = next;
	}
	*alst = NULL;
}
