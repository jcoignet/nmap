/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_biggest_node.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/10 01:55:53 by gbersac           #+#    #+#             */
/*   Updated: 2013/12/10 02:25:44 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t		ft_biggest_node(t_list *lst)
{
	size_t	to_return;

	to_return = 0;
	while (lst != NULL)
	{
		if (lst->content_size > to_return)
			to_return = lst->content_size;
		lst = lst->next;
	}
	return (to_return);
}
