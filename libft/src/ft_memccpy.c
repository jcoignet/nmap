/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:12:54 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:39:17 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *s1, const void *s2, int c, size_t n)
{
	char	*ptr1;
	char	*ptr2;
	size_t	i;

	if (s1 == NULL || s2 == NULL)
		return (NULL);
	ptr1 = (char*)s1;
	ptr2 = (char*)s2;
	i = 0;
	while (i < n)
	{
		if (ptr2[i] == (char)c)
		{
			ptr1[i] = ptr2[i];
			return (&(ptr1[i + 1]));
		}
		ptr1[i] = ptr2[i];
		++i;
	}
	return (NULL);
}
