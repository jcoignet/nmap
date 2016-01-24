/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:18:32 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:37:54 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *str, const char *to_find, size_t n)
{
	size_t	i;
	size_t	length;

	if (str == NULL || to_find == NULL)
		return (NULL);
	if (to_find[0] == '\0')
		return (char*)str;
	if (n == 0)
		return (NULL);
	length = ft_strlen(to_find);
	if (n < length)
		return (NULL);
	if (n > length)
		n = length;
	i = 0;
	while (str[i] != '\0')
	{
		if (!ft_strncmp(str + i, to_find, n))
			return (char*)(&(str[i]));
		++i;
	}
	return (NULL);
}
