/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lststr_merge.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/28 11:06:35 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:10:31 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static size_t	ttl_length(t_list *lst)
{
	size_t	length;

	length = 0;
	while (lst != NULL)
	{
		length += lst->content_size;
		lst = lst->next;
	}
	return (length);
}

char			*ft_lststr_merge(t_list *lst, const char *separator)
{
	size_t	length;
	size_t	nb_node;
	char	*to_return;

	if (lst == NULL)
		return (NULL);
	if (separator == NULL)
		separator = "";
	nb_node = ft_lstlen(lst);
	length = ttl_length(lst);
	length += (nb_node - 1) * ft_strlen(separator);
	to_return = (char*)malloc(length);
	to_return[0] = '\0';
	while (lst != NULL)
	{
		ft_strcat(to_return, separator);
		ft_strcat(to_return, (char*)lst->content);
		lst = lst->next;
	}
	return (to_return);
}
