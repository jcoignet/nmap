/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:13:58 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:13:29 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	*revmemcpy(void *s1, const void *s2, size_t n)
{
	char	*dst;
	char	*src;
	size_t	i;

	dst = (char*)s1;
	src = (char*)s2;
	i = n;
	while (i > 0)
	{
		dst[i - 1] = src[i - 1];
		--i;
	}
	return (s1);
}

void		*ft_memmove(void *dst, const void *src, size_t n)
{
	if (dst == NULL || src == NULL)
		return (NULL);
	if (dst == src)
		return (dst);
	if (dst < src)
		ft_memcpy(dst, src, n);
	else
		revmemcpy(dst, src, n);
	return (dst);
}
