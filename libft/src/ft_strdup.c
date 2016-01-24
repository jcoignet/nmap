/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:16:20 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:23:19 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strdup(const char *src)
{
	int		i;
	int		length;
	char	*str;

	if (src == NULL)
		return (NULL);
	length = ft_strlen(src);
	str = malloc(sizeof(*str) * (length + 1));
	i = 0;
	while (src[i] != '\0')
	{
		str[i] = src[i];
		++i;
	}
	str[i] = '\0';
	return (str);
}
