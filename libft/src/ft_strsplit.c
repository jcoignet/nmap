/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/30 12:40:04 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:37:37 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static size_t	length_word(char const *s, char c)
{
	size_t	i;

	i = 0;
	while (s[i] != c && s[i] != '\0')
		++i;
	return (i);
}

static size_t	count_word(char const *s, char c)
{
	size_t	n;
	size_t	i;
	int		in_word;

	i = 0;
	in_word = 0;
	n = 0;
	while (s[i] != '\0')
	{
		if (s[i] == c && in_word)
			in_word = !in_word;
		else if (s[i] != c && !in_word)
		{
			++n;
			in_word = !in_word;
		}
		++i;
	}
	return (n);
}

static char		**alloc_tab(size_t nb_word)
{
	char	**to_return;

	to_return = (char**)malloc((nb_word + 1) * sizeof(*to_return));
	if (to_return == NULL)
		return (NULL);
	to_return[0] = NULL;
	return (to_return);
}

static void		split(char **to_return, char const *s, char c)
{
	size_t	itab;
	char	*word;
	size_t	lw;

	itab = 0;
	while (*s != '\0')
	{
		lw = length_word(s, c);
		if (lw != 0)
		{
			word = ft_strsub(s, 0, lw);
			to_return[itab] = word;
			++itab;
		}
		s += lw;
		while (*s == c)
			++s;
	}
	to_return[itab] = NULL;
}

char			**ft_strsplit(char const *s, char c)
{
	char	**to_return;
	size_t	nb_word;

	if (s == NULL)
		return (alloc_tab(0));
	nb_word = count_word(s, c);
	to_return = alloc_tab(nb_word);
	if (to_return == NULL)
		return (NULL);
	split(to_return, s, c);
	return (to_return);
}
