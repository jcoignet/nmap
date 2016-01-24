/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nodenew.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 10:42:15 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:20:19 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_node	*ft_nodenew(void const *content, size_t content_size)
{
	t_node	*to_return;

	to_return = (t_node*)malloc(sizeof(t_node));
	to_return->content = (void*)content;
	to_return->content_size = content_size;
	to_return->parent = NULL;
	to_return->child = NULL;
	to_return->right = NULL;
	to_return->left = NULL;
	return (to_return);
}
