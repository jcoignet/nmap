/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_before.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/06 17:04:28 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/06 17:04:29 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t		ft_lst_before(t_list *lst)
{
	size_t	to_return;

	to_return = 0;
	while (lst != NULL)
	{
		++to_return;
		lst = lst->prev;
	}
	return (to_return);
}
