/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:15:13 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:21:55 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strchr(const char *s, int c)
{
	if (s == NULL)
		return (NULL);
	if (c < 0 || c > 255 || c == '\0')
		return (char *)(s + ft_strlen(s));
	while (*s != (char)c)
	{
		++s;
		if (*s == '\0')
			return (NULL);
	}
	return (char *)s;
}
