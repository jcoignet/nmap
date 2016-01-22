# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: jcoignet <jcoignet@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2015/11/17 18:32:43 by jcoignet          #+#    #+#              #
#    Updated: 2016/01/22 13:03:22 by jcoignet         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_nmap
GCC = gcc -Wall -Wextra -Werror
INCLUDES = ./includes/
SRCDIR = ./srcs/
SRCNAMES = main.c
SRC = $(addprefix $(SRCDIR), $(SRCNAMES))
OBJ = $(patsubst $(SRCDIR)%.c,%.o,$(SRC))

all: $(NAME)

$(NAME): $(OBJ)
	$(GCC) -o $(NAME) $(OBJ) -lpcap

$(OBJ): $(SRC)
	$(GCC) -c $(SRC) -I$(INCLUDES)

clean:
	rm -rf $(OBJ)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONE: clean fclean all re
