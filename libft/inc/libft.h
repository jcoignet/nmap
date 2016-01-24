/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gbersac <gbersac@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/30 12:40:04 by gbersac           #+#    #+#             */
/*   Updated: 2016/01/24 18:47:45 by gbersac          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
# define LIBFT_H
# define BUFF_SIZE 16

# include <stdlib.h>
# include <unistd.h>
# include <stdint.h>

typedef unsigned char	t_uchar;

void				*ft_memset(void *mem, int value, size_t size);
void				ft_bzero(void *mem, size_t size);
void				*ft_memcpy(void *dst, const void *src, size_t size);
void				*ft_memccpy(void *dst, const void *src, int c, size_t size);
void				*ft_memmove(void *dst, const void *src, size_t size);
void				*ft_memchr(const void *mem, int c, size_t size);

int					ft_memcmp(const void *mem1, const void *mem2, size_t size);
void				*ft_memalloc(size_t size);
void				ft_memdel(void **mem);

char				*ft_strdup(const char *str);
char				*ft_strmap(char const *s, char (*f)(char));
char				*ft_strmapi(char const *s, char (*f)(unsigned int, char));
char				*ft_strnew(size_t size);
void				ft_strdel(char **as);

/*
** Function which allocate a new string and fill it with the concat of
** the two strings in param and return it.
*/
char				*ft_strcup(char *s1, const char *s2);

char				*ft_strchr(const char *s, int c);
char				*ft_strrchr(const char *s, int c);
char				*ft_strstr(const char *s1, const char *s2);
char				*ft_strnstr(const char *s1, const char *s2, size_t size);
int					ft_strcmp(const char *s1, const char *s2);
int					ft_strncmp(const char *s1, const char *s2,
								unsigned int size);

int					ft_strequ(char const *s1, char const *s2);
int					ft_strnequ(char const *s1, char const *s2, size_t n);

char				*ft_strcpy(char *dst, const char *src);
char				*ft_strncpy(char *dst, const char *src, size_t size);
char				*ft_strcat(char *dst, const char *src);
char				*ft_strncat(char *dst, const char *src, size_t size);
size_t				ft_strlcat(char *dst, const char *src, size_t size);

size_t				ft_strlen(const char *str);
void				ft_strclr(char *s);
void				ft_striter(char *s, void (*f)(char *));
void				ft_striteri(char *s, void (*f)(unsigned int, char *));
char				*ft_strsub(char const *s, unsigned int start, size_t len);
char				*ft_strjoin(char const *s1, char const *s2);
char				**ft_strsplit(char const *s, char c);
char				*ft_itoa(int n);
char				*ft_itoa_hex(uint64_t n, int is_upcase);
int					ft_atoi(const char *str);
int					ft_toupper(int c);
int					ft_tolower(int c);
char				*ft_strtrim(char const *s);

/*
** Function which return a fresh string of size == lg and which added char
** are the filler char and are positionnes on the left if on_right == false,
** on the right otherwise.
*/
char				*ft_strextend(char *model, char filler, size_t lg,
							t_uchar on_right);

int					ft_isalpha(int c);
int					ft_isdigit(int c);
int					ft_isalnum(int c);
int					ft_isascii(int c);
int					ft_isprint(int c);

void				ft_putchar(char c);
void				ft_putstr(char const *s);
void				ft_putendl(char const *s);
void				ft_putnbr(int n);
void				ft_putchar_fd(char c, int fd);
void				ft_putstr_fd(char const *s, int fd);
void				ft_putendl_fd(char const *s, int fd);
void				ft_putnbr_fd(int n, int fd);

typedef struct		s_list
{
	void			*content;
	size_t			content_size;
	struct s_list	*next;
	struct s_list	*prev;
}					t_list;

/*
** Allocate a new node and fill it with a copy of content which size is
** content_size.
*/
t_list				*ft_lstnew(void *content, size_t content_size);

/*
** Create a new list node and push it at the end of dest.
** Copy content in the new list node.
** return a pointer to the newly created node.
*/
t_list				*ft_push_back(t_list **dest, void *content, size_t size);

/*
** Delete the node alst and all its followers.
*/
void				ft_lstdel(t_list **alst, void (*del)(void *));

/*
** Function which add a node at the beginning of the list
** Doesn't set new->previous == NULL. Usefull to merge two lists.
*/
void				ft_lstadd(t_list **alst, t_list *n);

void				ft_lstaddq(t_list **alst, t_list *n);

/*
** Append l2 at the end of l1.
** @return l1 or NULL if l1 pr l2 is NULL.
*/
t_list				*ft_lstmerge(t_list *l1, t_list *l2);

/*
** Create a new list by applying the f function on each of the node of
** the lst list.
*/
t_list				*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem));

size_t				ft_lstlen(t_list *lst);

/*
** Return the number of element in the list before lst (lst include).
*/
size_t				ft_lst_before(t_list *lst);

/*
** Return the number of element in the list after lst (lst include).
*/
size_t				ft_lst_after(t_list *lst);

/*
** Delete the node and its content. The content is deleted using the
** del function.
*/
void				ft_lstdelone(t_list **alst, void (*del)(void *));

/*
** Delete the node number n in the list. The first node is of index 0.
*/
void				ft_lstdelnode(t_list **lst, size_t n,
									void (*del)(t_list *));

/*
** Return the content of the list node number i. Index start at 0.
*/
void				*ft_lst_get(t_list *lst, size_t i);

void				ft_lstiter(t_list *lst, void (*f)(t_list *elem));
t_list				*ft_lst_last(t_list *lst);
t_list				*ft_lst_first(t_list *lst);

/*
** Sort the list using the merge sort algorithm.
** @lst	list to sort
** @cmp	function which return true if element need to inverted. ie : l2 must be
** 		before l1.
*/
t_list				*ft_mergesort(t_list *lst,
								t_uchar (*f)(t_list *, t_list *));

/*
** Function which return the size of the biggest node of the list.
*/
size_t				ft_biggest_node(t_list *lst);

/*
** Function which rotate the list, first becomming last.
*/
void				ft_lst_rotate(t_list **lst);

void				ft_lst_insert_b(t_list **lst, t_list *to_insert);
void				ft_lst_insert_a(t_list **lst, t_list *to_insert);

/*
** Function which add a node the beginning of the list
** Doesn't set new->previous == NULL. Usefull to merge two lists.
*/
void				ft_clstadd(t_list **alst, t_list *l);

void				ft_clstaddq(t_list **alst, t_list *l);

size_t				ft_clstlen(t_list *lst);

/*
** Convert a circular list into a regular list.
*/
void				ft_circ_to_regular(t_list *lst);

/*
** Split the str string according to the c char and create a list
*/
t_list				*ft_strsplit_lst(const char *str, char separator);

/*
** Display all the str in the list on the terminal.
** Warning : all content of each node are supposed to be string !
*/
void				ft_putlststr(t_list *lst, const char *separator);

/*
** Display all the str in the list on the file fd.
** Warning : all content of each node are supposed to be string !
*/
void				ft_putlststr_fd(t_list *lst, int fd, const char *separator);

/*
** Return one new string which is the concatenation of all the content of
** all the string in the list separate by the separator string.
*/
char				*ft_lststr_merge(t_list *lst, const char *separator);

/*
** Function which make sure that each of the string within the list have a
** length equal to the length of the biggest string in the list.
** It fill the missing char with space char.
** @lst			list to equalise.
** @on_right	if true, the space char to add will be add on the right of the
** 				string, on the left otherwise.
*/
void				ft_lststr_equalise(t_list *lst, t_uchar on_right);

/*
** Doesn't copy the string into the memory. The str pointer will be affected to
** the new node of the list.
*/
void				ft_slstadd(t_list **lst, char *str);
void				ft_slstaddq(t_list **lst, char *str);

/*
** Transform a list of string into a char**
*/
char				**ft_lststr_to_tab(t_list *lst);

typedef struct		s_node
{
	struct s_node	*parent;
	struct s_node	*child;
	struct s_node	*right;
	struct s_node	*left;
	void			*content;
	size_t			content_size;
}					t_node;

t_node				*ft_nodenew(void const *content, size_t content_size);
int					ft_nodedelone(t_node **anode, void (*del)(void *, size_t));

/*
** Delete the root and all the son of anode but not their content.
*/
void				ft_nodedel(t_node **anode);
void				ft_nodeaddchild(t_node *parent, t_node *newe);
void				ft_nodeaddright(t_node **brother, t_node *newe);
t_node				*ft_get_node(t_node *tree, int x, int y);

typedef struct		s_dividelst
{
	t_list			*l1;
	t_list			*l2;
}					t_dividelst;

typedef struct		s_buffer
{
	void			*data;
	size_t			size;
}					t_buffer;

int					get_next_line(int const fd, char **line);
uint32_t			ft_swap_uint32(uint32_t d);

#endif
