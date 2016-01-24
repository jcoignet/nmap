/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/25 16:39:37 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:25:44 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnew(size_t size)
{
	size_t	i;
	char	*to_return;

	to_return = (char*)malloc((size + 1) * sizeof(char));
	if (to_return == NULL)
		return (NULL);
	i = 0;
	while (i < size)
	{
		to_return[i] = 0;
		++i;
	}
	to_return[size] = '\0';
	return (to_return);
}
