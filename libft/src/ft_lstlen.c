/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstlen.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 16:11:56 by gbersac           #+#    #+#             */
/*   Updated: 2015/07/29 16:00:28 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include "libft.h"

size_t		ft_lstlen(t_list *lst)
{
	size_t	length;

	if (lst == NULL)
		return (0);
	lst = ft_lst_first(lst);
	length = 0;
	while (lst != NULL)
	{
		++length;
		lst = lst->next;
	}
	return (length);
}
