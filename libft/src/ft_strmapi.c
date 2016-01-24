/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/25 16:39:37 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:38:03 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmapi(char const *s, char (*f)(unsigned int, char))
{
	size_t	i;
	size_t	length;
	char	*to_return;

	if (s == NULL || f == NULL)
		return (NULL);
	i = 0;
	length = ft_strlen(s);
	to_return = (char*)malloc((length + 1) * sizeof(s));
	while (s[i] != '\0')
	{
		to_return[i] = f(i, s[i]);
		++i;
	}
	to_return[i] = '\0';
	return (to_return);
}
