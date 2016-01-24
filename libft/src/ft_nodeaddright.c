/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nodeaddright.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/15 21:06:05 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/09 19:33:08 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_nodeaddright(t_node **bro, t_node *newe)
{
	t_node	*iter;

	if (newe == NULL)
		return ;
	if (*bro == NULL)
	{
		*bro = newe;
		return ;
	}
	iter = *bro;
	while (iter->right != NULL)
		iter = iter->right;
	iter->right = newe;
	newe->left = iter;
}
