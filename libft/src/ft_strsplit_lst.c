/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit_lst.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/24 14:12:05 by gbersac           #+#    #+#             */
/*   Updated: 2013/12/28 16:14:55 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_strsplit_lst(const char *str, char separator)
{
	char	**tab_word;
	size_t	i;
	t_list	*newe;
	t_list	*lst;

	if (str == NULL)
		return (NULL);
	tab_word = ft_strsplit(str, separator);
	i = 0;
	lst = NULL;
	while (tab_word[i] != NULL)
	{
		newe = ft_lstnew(tab_word[i], ft_strlen(tab_word[i]) + 1);
		ft_lstaddq(&lst, newe);
		++i;
	}
	if (tab_word != NULL)
		free(tab_word);
	return (lst);
}
