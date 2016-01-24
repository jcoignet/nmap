/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nodeaddchild.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 11:43:21 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/09 19:31:14 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_nodeaddchild(t_node *parent, t_node *new)
{
	t_node	*right;

	if (parent == NULL)
		return ;
	right = parent->child;
	while (right->right != NULL)
		right = right->right;
	right->right = new;
	new->left = right;
}
