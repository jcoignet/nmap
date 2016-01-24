/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nodedel.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 10:42:15 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/09 20:59:49 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_nodedel(t_node **anode)
{
	t_node	*node;

	node = *anode;
	if (node->child != NULL)
		ft_nodedel(&(node->child));
	if (node->right != NULL)
		ft_nodedel(&(node->right));
	free(node);
	*anode = NULL;
}
