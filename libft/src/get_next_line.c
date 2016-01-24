/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/02 15:47:38 by gbersac           #+#    #+#             */
/*   Updated: 2014/04/26 23:35:15 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void			*memjoin(void *mem1, size_t l1, void *mem2, size_t l2)
{
	void	*to_return;

	if (mem1 == NULL || l1 == 0)
	{
		l1 = 0;
		to_return = malloc(l2 + 1);
		ft_memcpy(to_return, mem2, l2);
	}
	else if (mem2 == NULL || l2 == 0)
	{
		l2 = 0;
		to_return = malloc(l1 + 1);
		ft_memcpy(to_return, mem1, l1);
	}
	else
	{
		to_return = malloc(l1 + l2 + 1);
		ft_memcpy(to_return, mem1, l1);
		ft_memcpy(to_return + l1, mem2, l2);
	}
	((char*)to_return)[l1 + l2] = '\0';
	return (to_return);
}

static int			end(t_buffer *buffer,
						t_buffer **svg,
						void *end_line,
						size_t lgbuff)
{
	if (*svg)
	{
		free((*svg)->data);
		free(*svg);
		*svg = NULL;
	}
	if (end_line)
	{
		*svg = (t_buffer*)malloc(sizeof(t_buffer));
		(*svg)->size = buffer->size - lgbuff - 1;
		(*svg)->data = malloc((*svg)->size);
		ft_memcpy((*svg)->data, ++end_line, (*svg)->size);
	}
	if (buffer->size == 0 && !(*svg))
		return (-1);
	if (end_line || buffer->size == 0)
		return (0);
	return (1);
}

static int			select_buffer(int fd,
									t_buffer **buffer,
									t_buffer *svg_buffer)
{
	int				read_result;

	if (!svg_buffer || svg_buffer->data == NULL || svg_buffer->size == 0)
	{
		read_result = read(fd, (*buffer)->data, BUFF_SIZE);
		if (read_result == -1)
			return (-2);
		(*buffer)->size = read_result;
	}
	else
	{
		free((*buffer)->data);
		(*buffer)->data = malloc(svg_buffer->size);
		ft_memcpy((*buffer)->data, svg_buffer->data, svg_buffer->size);
		(*buffer)->size = svg_buffer->size;
	}
	return (0);
}

static int			read_line(t_buffer *buffer,
								int fd,
								char **line,
								size_t *lgl)
{
	void			*nvline;
	void			*end_line;
	size_t			lg_valid_buffer;
	static t_buffer	*svg_buffer = NULL;

	if (select_buffer(fd, &buffer, svg_buffer) == -2)
		return (-2);
	end_line = ft_memchr(buffer->data, '\n', buffer->size);
	if (end_line == NULL)
		lg_valid_buffer = buffer->size;
	else
		lg_valid_buffer = end_line - buffer->data;
	nvline = memjoin(*line, *lgl, buffer->data, lg_valid_buffer);
	free(*line);
	*line = nvline;
	*lgl += lg_valid_buffer;
	return (end(buffer, &svg_buffer, end_line, lg_valid_buffer));
}

int					get_next_line(int const fd, char **line)
{
	t_buffer	buffer;
	int			result_read;
	size_t		lg_line;

	result_read = 1;
	lg_line = 0;
	buffer.data = malloc(BUFF_SIZE + 1);
	*line = NULL;
	while (result_read > 0)
		result_read = read_line(&buffer, fd, line, &lg_line);
	free(buffer.data);
	if (result_read == -1)
		return (0);
	if (result_read == -2)
		return (-1);
	return (1);
}
