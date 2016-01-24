/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdelone.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/24 11:37:11 by gbersac           #+#    #+#             */
/*   Updated: 2014/01/05 21:50:46 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_lstdelone(t_list **alst, void (*del)(void *))
{
	t_list	*prev;
	t_list	*next;

	if (del == NULL || alst == NULL || *alst == NULL)
		return ;
	prev = (*alst)->prev;
	next = (*alst)->next;
	if (prev != NULL && prev != (*alst))
		prev->next = next;
	if (next != NULL && next != (*alst))
		next->prev = prev;
	del((**alst).content);
	free(*alst);
	*alst = NULL;
}
