/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_slstadd.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/18 16:58:12 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:21:05 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_slstadd(t_list **lst, char *str)
{
	t_list	*newe;

	if (lst == NULL || str == NULL)
		return ;
	newe = (t_list*)malloc(sizeof(t_list));
	newe->content = str;
	newe->prev = NULL;
	newe->next = *lst;
	*lst = newe;
}
