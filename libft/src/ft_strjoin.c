/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/25 16:39:37 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:23:52 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strjoin(char const *s1, char const *s2)
{
	char	*to_return;
	size_t	length;

	if (s1 == NULL || s2 == NULL)
		return (NULL);
	length = ft_strlen(s1) + ft_strlen(s2);
	to_return = (char*)malloc((length + 1) * sizeof(char));
	if (to_return == NULL)
		return (NULL);
	ft_strcpy(to_return, s1);
	ft_strcat(to_return, s2);
	to_return[length] = '\0';
	return (to_return);
}
