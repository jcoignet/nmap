/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lststr_equalise.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/10 01:55:23 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:09:18 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_lststr_equalise(t_list *lst, t_uchar on_right)
{
	size_t	maxl;

	if (lst == NULL)
		return ;
	maxl = ft_biggest_node(lst);
	while (lst != NULL)
	{
		lst->content = ft_strextend((char*)lst->content, ' ', maxl, on_right);
		lst = lst->next;
	}
}
