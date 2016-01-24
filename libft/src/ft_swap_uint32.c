/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_swap_uint32.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/26 21:46:37 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 21:52:54 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

uint32_t	ft_swap_uint32(uint32_t d)
{
	uint32_t		a;
	unsigned char	*dst;
	unsigned char	*src;

	dst = (unsigned char*)&a;
	src = (unsigned char*)&d;
	dst[0] = src[3];
	dst[1] = src[2];
	dst[2] = src[1];
	dst[3] = src[0];
	return (a);
}
