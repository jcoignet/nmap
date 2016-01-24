/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_hex.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/24 15:07:31 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:06:59 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static uint64_t	pow_16(size_t pw)
{
	uint64_t	to_return;
	size_t		i;

	i = 0;
	to_return = 1;
	while (i < pw && to_return <= 1152921504606846976)
	{
		to_return = to_return * 16;
		++i;
	}
	return (to_return);
}

static char		get_char(unsigned char digit, int is_upcase)
{
	if (digit <= 9)
		return (digit + '0');
	digit -= 10;
	if (is_upcase)
		return (digit + 'A');
	else
		return (digit + 'a');
}

static void		print_num(size_t num_digit,
						uint64_t n,
						char *to_return,
						int is_upcase)
{
	size_t			i;
	size_t			istr;
	unsigned char	digit;

	i = num_digit;
	istr = 0;
	while (i > 0)
	{
		digit = n / pow_16(i - 1);
		n = n % pow_16(i - 1);
		to_return[istr] = get_char(digit, is_upcase);
		++istr;
		--i;
	}
	to_return[num_digit] = '\0';
}

char			*ft_itoa_hex(uint64_t n, int is_upcase)
{
	char		*to_return;
	size_t		num_digit;
	uint64_t	nb;

	num_digit = 1;
	nb = n;
	if (n > 1152921504606846976)
		num_digit = 15;
	else
	{
		while (pow_16(num_digit) <= nb)
			++num_digit;
	}
	to_return = malloc(num_digit + 2);
	if (to_return == NULL)
		return (NULL);
	print_num(num_digit, nb, to_return, is_upcase);
	return (to_return);
}
