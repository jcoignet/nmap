/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_mergesort.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/30 12:40:04 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:38:26 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static t_dividelst	*dividelst(t_list *lst)
{
	size_t		middle;
	size_t		i;
	t_dividelst	*to_return;

	to_return = (t_dividelst*)malloc(sizeof(t_dividelst));
	middle = ft_lstlen(lst) / 2;
	to_return->l1 = lst;
	i = 1;
	while (lst != NULL && i < middle)
	{
		lst = lst->next;
		++i;
	}
	to_return->l2 = lst->next;
	if (lst->next != NULL)
		lst->next->prev = NULL;
	lst->next = NULL;
	return (to_return);
}

static t_list		*insert(t_list *lst,
						t_list *elem,
						t_uchar (*cmp)(t_list*, t_list*))
{
	t_list	*previous;

	if (cmp(lst, elem))
	{
		elem->next = lst;
		lst->prev = elem;
		return (elem);
	}
	previous = NULL;
	while (lst != NULL && !cmp(lst, elem))
	{
		previous = lst;
		lst = lst->next;
	}
	if (previous != NULL)
		previous->next = elem;
	elem->next = lst;
	elem->prev = previous;
	if (lst != NULL)
		lst->prev = elem;
	return (ft_lst_first(previous));
}

static t_list		*merge(t_list *l1,
							t_list *l2,
							t_uchar (*f)(t_list*, t_list*))
{
	t_list	*next;

	if (l1 == NULL)
		return (l2);
	if (l2 == NULL)
		return (l1);
	next = l2->next;
	l1 = insert(l1, l2, f);
	return (merge(l1, next, f));
}

t_list				*ft_mergesort(t_list *lst, t_uchar (*cmp)(t_list*, t_list*))
{
	t_dividelst	*part;
	t_list		*result1;
	t_list		*result2;
	t_list		*res;

	if (ft_lstlen(lst) <= 1)
		return (lst);
	part = dividelst(lst);
	result1 = ft_mergesort(part->l1, cmp);
	result2 = ft_mergesort(part->l2, cmp);
	free(part);
	res = merge(result1, result2, cmp);
	return (res);
}
