# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2015/11/17 18:32:43 by jcoignet          #+#    #+#              #
#    Updated: 2016/01/24 18:45:32 by gbersac          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_nmap
GCC = gcc -Wall -Wextra -Werror
INCLUDES = ./includes/
SRCDIR = ./srcs/
SRCNAMES = main.c
SRC = $(addprefix $(SRCDIR), $(SRCNAMES))
OBJ = $(patsubst $(SRCDIR)%.c,%.o,$(SRC))

.PHONY: all $(NAME) libft

all:  $(NAME)

libft:
	@echo \	MAKE in directory : $@
	@$(MAKE) --directory=$@

$(NAME): $(OBJ) libft
	$(GCC) -o $(NAME) $(OBJ) -lpcap -Llibft -lft

$(OBJ): $(SRC)
	$(GCC) -c $(SRC) -I$(INCLUDES) -I./libft/inc

clean:
	rm -rf $(OBJ)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONE: clean fclean all re
