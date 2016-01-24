/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putlststr.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/24 14:09:18 by gbersac           #+#    #+#             */
/*   Updated: 2013/12/28 16:15:45 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_putlststr(t_list *lst, const char *separator)
{
	if (lst == NULL)
		return ;
	ft_putlststr_fd(lst, 1, separator);
}
