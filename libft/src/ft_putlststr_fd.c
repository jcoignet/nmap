/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putlststr_fd.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/30 12:40:04 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:20:43 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_putlststr_fd(t_list *lst, int fd, const char *separator)
{
	char	*str;

	if (lst == NULL)
		return ;
	while (lst != NULL)
	{
		str = (char*)lst->content;
		ft_putstr_fd(str, fd);
		if (lst->next != NULL)
			ft_putstr_fd(separator, fd);
		lst = lst->next;
	}
}
