/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_clstlen.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/02 21:38:26 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/02 22:35:07 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t		ft_clstlen(t_list *lst)
{
	t_list	*iter;
	int		i;

	if (lst == NULL)
		return (0);
	iter = lst->next;
	i = 1;
	while (iter != lst)
	{
		++i;
		iter = iter->next;
	}
	return (i);
}
