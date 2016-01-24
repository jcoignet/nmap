/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/30 12:40:04 by gbersac           #+#    #+#             */
/*   Updated: 2015/08/12 13:40:09 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int			is_blank(char c)
{
	return ((c == ' ') || (c == '\t') || (c == '\n'));
}

static const char	*seek_end(const char *str)
{
	str = str + ft_strlen(str);
	while (is_blank(*(str - 1)))
		--str;
	return (str);
}

static const char	*seek_begin(const char *str)
{
	while (is_blank(*str))
		++str;
	return (str);
}

char				*ft_strtrim(char const *s)
{
	char		*to_return;
	const char	*begin;
	const char	*end;

	if (s == NULL)
		return (NULL);
	if (!ft_strcmp(s, ""))
		return (ft_strdup(""));
	begin = seek_begin(s);
	end = seek_end(s);
	if (begin >= end)
		return (ft_strdup(""));
	to_return = ft_strsub(begin, 0, (size_t)(end - begin));
	if (to_return == NULL)
	{
		to_return = (char*)malloc(1);
		to_return[0] = '\0';
	}
	return (to_return);
}
