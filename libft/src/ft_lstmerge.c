/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmerge.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 12:12:58 by gbersac           #+#    #+#             */
/*   Updated: 2013/12/02 15:59:28 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list		*ft_lstmerge(t_list *l1, t_list *l2)
{
	t_list	*last_l1;

	if (l1 == NULL || l2 == NULL)
		return (NULL);
	last_l1 = ft_lst_last(l1);
	last_l1->next = l2;
	return (l1);
}
