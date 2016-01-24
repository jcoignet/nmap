/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:13:11 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:38:56 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	char	*ptr;
	size_t	i;

	if (s == NULL)
		return (NULL);
	i = 0;
	ptr = (char*)s;
	while (i < n)
	{
		if (ptr[i] == (unsigned char)c)
			return (&(ptr[i]));
		++i;
	}
	return (NULL);
}
