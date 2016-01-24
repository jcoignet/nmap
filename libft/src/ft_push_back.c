/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_push_back.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/07/28 20:29:34 by gbersac           #+#    #+#             */
/*   Updated: 2015/08/12 13:39:28 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list				*ft_push_back(t_list **dest, void *content, size_t size)
{
	t_list	*newl;

	newl = ft_lstnew(content, size);
	ft_lstaddq(dest, newl);
	return (newl);
}
