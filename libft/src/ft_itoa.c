/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/30 12:40:04 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:06:29 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static long	pow_10(size_t pw)
{
	long	to_return;
	size_t	i;

	i = 0;
	to_return = 1;
	while (i < pw)
	{
		to_return = to_return * 10;
		++i;
	}
	return (to_return);
}

static void	print_num(size_t num_digit, long n, char *to_return)
{
	size_t			i;
	size_t			istr;
	unsigned char	digit;

	i = num_digit;
	istr = 0;
	while (i > 0)
	{
		digit = n / pow_10(i - 1);
		n = n % pow_10(i - 1);
		to_return[istr] = digit + '0';
		++istr;
		--i;
	}
	to_return[num_digit] = '\0';
}

char		*ft_itoa(int n)
{
	char	*to_return;
	size_t	num_digit;
	int		is_neg;
	long	nb;

	num_digit = 1;
	nb = n;
	if ((is_neg = (nb < 0)))
		nb = -nb;
	while (pow_10(num_digit) <= nb)
		++num_digit;
	to_return = malloc(num_digit + 2);
	if (to_return == NULL)
		return (NULL);
	if (is_neg)
	{
		to_return[0] = '-';
		print_num(num_digit, nb, to_return + 1);
	}
	else
		print_num(num_digit, nb, to_return);
	return (to_return);
}
