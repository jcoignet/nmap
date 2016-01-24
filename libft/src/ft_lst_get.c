/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_get.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/07/28 20:56:17 by gbersac           #+#    #+#             */
/*   Updated: 2015/07/29 18:48:07 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include "libft.h"

void				*ft_lst_get(t_list *lst, size_t i)
{
	t_list	*iter;
	size_t	nb_loop;

	if (lst == NULL)
		return (NULL);
	iter = lst;
	nb_loop = 0;
	while (iter != NULL)
	{
		if (nb_loop == i)
			return (iter->content);
		iter = iter->next;
		++nb_loop;
	}
	return (NULL);
}
