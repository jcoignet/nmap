/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lststr_to_tab.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/23 01:01:58 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:11:04 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		**ft_lststr_to_tab(t_list *lst)
{
	int		lg;
	char	**to_return;
	int		i;

	lg = ft_lstlen(lst);
	to_return = (char**)malloc(sizeof(char*) * (lg + 1));
	i = 0;
	while (i < lg)
	{
		to_return[i] = ft_strdup((char*)lst->content);
		lst = lst->next;
		++i;
	}
	to_return[i] = NULL;
	return (to_return);
}
