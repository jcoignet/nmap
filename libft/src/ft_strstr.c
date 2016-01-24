/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 20:19:09 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:37:05 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *str, const char *to_find)
{
	int		i;
	int		j;
	int		diff_found;

	if (to_find[0] == '\0')
		return (char*)str;
	i = 0;
	while (str[i] != '\0')
	{
		j = 0;
		diff_found = 0;
		while (to_find[j] != '\0' && diff_found == 0)
		{
			if (to_find[j] != str[i + j])
				diff_found = 1;
			if (str[i + j] == '\0')
				return (NULL);
			++j;
		}
		if (!diff_found)
			return (char*)(&(str[i]));
		++i;
	}
	return (0);
}
