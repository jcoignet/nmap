################################################################################
# SOURCES       															   #
################################################################################

SRCS_MEMORY	= ft_memset.c ft_bzero.c ft_memcpy.c ft_memccpy.c \
				ft_memmove.c ft_memchr.c ft_memcmp.c
SRCS_STR	= ft_strlen.c ft_strdup.c ft_strchr.c ft_strrchr.c \
				ft_strstr.c ft_strnstr.c ft_strcmp.c ft_strncmp.c \
				ft_strcpy.c ft_strncpy.c ft_strcat.c ft_strncat.c \
				ft_strlcat.c ft_strtrim.c ft_strextend.c
SRCS_TEST	= ft_atoi.c ft_isalpha.c ft_isdigit.c ft_isalnum.c \
				ft_isascii.c ft_isprint.c ft_toupper.c ft_tolower.c
SRCS_AUTRES	= ft_memalloc.c ft_memdel.c ft_strnew.c ft_strdel.c \
				ft_strclr.c ft_striter.c ft_striteri.c ft_strmap.c \
				ft_strmapi.c ft_strequ.c ft_strnequ.c ft_strsub.c \
				ft_strjoin.c ft_strjoin.c ft_strsplit.c ft_itoa.c \
				ft_putchar.c ft_putstr.c ft_putendl.c ft_putnbr.c \
				ft_putchar_fd.c ft_putstr_fd.c ft_putendl_fd.c \
				ft_putnbr_fd.c ft_itoa_hex.c
SRCS_LIST	= ft_lstnew.c ft_lstdelone.c ft_lstdel.c ft_lstadd.c \
				ft_lstiter.c ft_lstmap.c ft_lst_last.c ft_lstmerge.c \
				ft_mergesort.c ft_lststr_equalise.c ft_biggest_node.c \
				ft_lst_rotate.c ft_lstdelnode.c ft_lstlen.c ft_lst_first.c \
				ft_lst_before.c ft_lst_after.c ft_slstadd.c ft_slstaddq.c \
				ft_lststr_to_tab.c ft_lst_insert_b.c ft_lst_insert_a.c \
				ft_push_back.c ft_lst_get.c
SRCS_CLIST	= ft_clstadd.c ft_clstaddq.c ft_clstlen.c ft_circ_to_regular.c
SRCS_TREE	= ft_nodenew.c ft_nodedelone.c ft_nodedel.c ft_nodeaddchild.c \
				ft_nodeaddright.c ft_get_node.c
SRCS_PERSO	= ft_putlststr.c ft_putlststr_fd.c ft_strsplit_lst.c ft_lstaddq.c \
				ft_strcup.c ft_lststr_merge.c
SRCS_READ	= get_next_line.c ft_swap_uint32.c

SRCS		= $(SRCS_MEMORY) $(SRCS_STR) $(SRCS_TEST) $(SRCS_AUTRES) \
				$(SRCS_PERSO) $(SRCS_TREE) $(SRCS_READ) $(SRCS_LIST) \
				$(SRCS_CLIST)

################################################################################
# BASIC VARIABLES															   #
################################################################################

PATH_OBJ	= obj
PATH_SRC	= src
PATH_INC	= inc

NAME		= libft.a
CFLAGS		= -Wall -Wextra -Werror
OBJECTS		= $(patsubst %.c, $(PATH_OBJ)/%.o, $(SRCS))
DEBUG		= -g -O0

################################################################################
# RULES																		   #
################################################################################

.PHONY: all

all: $(NAME)

$(NAME): $(OBJECTS)
	@ar rc $@ $(OBJECTS)
	@ranlib $(NAME)
	@echo Creating Library $(NAME) $(words $(OBJECTS)) files inside

$(PATH_OBJ)/%.o: $(addprefix $(PATH_SRC)/,%.c)
	@mkdir -p $(PATH_OBJ)
	$(CC) -c -o $@ $(CFLAGS) $^ -O0 -g  -I $(PATH_INC)/

test:

clean:
	@rm -f $(OBJECTS)
	@echo Delete $(words $(OBJECTS)) object file

fclean: clean
	rm -f $(NAME)

re: fclean $(NAME)
