/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_after.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/06 17:07:03 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/06 17:30:59 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t		ft_lst_after(t_list *lst)
{
	size_t	to_return;

	to_return = 0;
	while (lst != NULL)
	{
		++to_return;
		lst = lst->next;
	}
	return (to_return);
}
