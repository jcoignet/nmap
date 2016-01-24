/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nodedelone.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 10:42:15 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:19:37 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	change_father_child(t_node *to_del)
{
	if (to_del->parent == NULL)
		return ;
	if (to_del->parent->child == to_del)
		to_del->parent->child = to_del->right;
}

static int	exclude_brother(t_node *prev, t_node *to_del)
{
	if (prev == NULL)
		return (0);
	prev->right = to_del->right;
	return (0);
}

static int	exclude_from_brother(t_node *to_del)
{
	t_node	*parent;
	t_node	*right;
	t_node	*prev_brother;

	parent = to_del->parent;
	if (parent == NULL)
		return (0);
	right = parent->child;
	prev_brother = NULL;
	while (right != NULL)
	{
		if (right == to_del)
			return (exclude_brother(prev_brother, to_del));
		prev_brother = right;
		right = right->right;
	}
	return (1);
}

int			ft_nodedelone(t_node **anode, void (*del)(void *, size_t))
{
	t_node	*to_del;
	int		ret;

	if (anode == NULL || *anode == NULL)
		return (0);
	to_del = *anode;
	del(to_del->content, to_del->content_size);
	ret = exclude_from_brother(to_del);
	if (ret != 0)
		return (ret);
	change_father_child(to_del);
	return (0);
}
