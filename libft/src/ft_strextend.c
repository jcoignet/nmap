/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strextend.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/10 22:35:54 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:23:36 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	add_space(char *str, int nb_filler, char filler)
{
	int	i;

	if (nb_filler <= 0)
		return ;
	i = 0;
	while (i <= nb_filler)
	{
		str[i] = filler;
		++i;
	}
}

static void	modify_left(char *new_str, char *model, int nb_filler, char filler)
{
	add_space(new_str, nb_filler, filler);
	ft_strcpy(new_str + nb_filler, model);
}

static void	modify_right(char *new_str, char *model, int nb_filler, char filler)
{
	ft_strcpy(new_str, model);
	add_space(new_str + ft_strlen(model), nb_filler, filler);
}

char		*ft_strextend(char *model,
							char filler,
							size_t lg,
							t_uchar on_right)
{
	char	*new_str;
	int		nb_filler;

	nb_filler = lg - ft_strlen(model);
	if (nb_filler <= 0)
		return (ft_strdup(model));
	new_str = (char*)malloc(lg + 2);
	if (on_right)
		modify_right(new_str, model, nb_filler, filler);
	else
		modify_left(new_str, model, nb_filler, filler);
	new_str[lg] = '\0';
	return (new_str);
}
