/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_circ_to_regular.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/01/04 15:31:20 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/04 16:05:15 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_circ_to_regular(t_list *lst)
{
	if (lst == NULL)
		return ;
	lst->prev->next = NULL;
	lst->prev = NULL;
}
