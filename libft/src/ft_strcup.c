/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 10:55:30 by gbersac           #+#    #+#             */
/*   Updated: 2015/01/29 18:00:34 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		*ft_strcup(char *s1, const char *s2)
{
	char	*to_return;
	size_t	length;

	if (s1 == NULL && s2 == NULL)
		return (NULL);
	if (s2 == NULL)
		return (ft_strdup(s1));
	if (s1 == NULL)
		return (ft_strdup(s2));
	length = ft_strlen(s1) + ft_strlen(s2) + 1;
	to_return = (char*)malloc(length * sizeof(char));
	ft_strcpy(to_return, s1);
	ft_strcat(to_return, s2);
	return (to_return);
}
