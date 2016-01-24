/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:18:14 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:25:31 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncpy(char *dest, const char *src, size_t n)
{
	unsigned int		i;

	i = 0;
	if (dest == NULL || src == NULL)
		return (NULL);
	while (i < n && src[i] != '\0')
	{
		dest[i] = src[i];
		++i;
	}
	dest[i] = '\0';
	if (i < n)
	{
		while (i < n)
		{
			dest[i] = '\0';
			++i;
		}
	}
	return (dest);
}
