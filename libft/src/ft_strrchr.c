/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:18:51 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:37:47 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *s, int c)
{
	int		i;
	char	*str;

	if (s == NULL)
		return (NULL);
	i = ft_strlen(s);
	if (c < 0 || c > 255 || c == '\0')
		return (char*)(s + i);
	while (s[i] != (char)c && i >= 0)
		--i;
	if (i < 0)
		return (NULL);
	str = (char*)(s + i);
	return (str);
}
