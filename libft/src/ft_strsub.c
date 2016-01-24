/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/25 16:39:37 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:29:25 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub(char const *s, unsigned int start, size_t len)
{
	char	*to_return;
	size_t	i;

	if (s == NULL)
		return (NULL);
	i = 0;
	s = s + start;
	to_return = (char*)malloc((len + 1) * sizeof(char));
	if (to_return == NULL)
		return (NULL);
	while (i < len)
	{
		to_return[i] = s[i];
		++i;
	}
	to_return[len] = '\0';
	return (to_return);
}
