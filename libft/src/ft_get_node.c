/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_get_node.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/14 20:17:17 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/14 20:19:21 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_node		*ft_get_node(t_node *tree, int x, int y)
{
	int		ix;
	int		iy;

	if (tree == NULL || x < 0 || y < 0)
		return (NULL);
	iy = 0;
	while (iy < y)
	{
		if (tree == NULL)
			return (NULL);
		++iy;
		tree = tree->child;
	}
	if (tree == NULL)
		return (NULL);
	ix = 0;
	while (ix < x)
	{
		if (tree == NULL)
			return (NULL);
		++ix;
		tree = tree->right;
	}
	return (tree);
}
