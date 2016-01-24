/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/25 16:39:37 by gbersac           #+#    #+#             */
/*   Updated: 2015/07/29 15:52:44 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list		*ft_lstnew(void *content, size_t content_size)
{
	t_list	*to_return;

	to_return = (t_list*)malloc(sizeof(t_list));
	if (to_return == NULL)
		return (NULL);
	if (content == NULL)
	{
		to_return->content_size = 0;
		to_return->content = NULL;
	}
	else
	{
		to_return->content_size = content_size;
		to_return->content = (unsigned char*)malloc(content_size *
				sizeof(unsigned char));
		ft_memcpy(to_return->content, content, content_size);
	}
	to_return->next = NULL;
	to_return->prev = NULL;
	return (to_return);
}
