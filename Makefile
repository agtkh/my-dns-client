NAME = dns-client
CC = gcc
CFLAGS = -O3 -Wall
SRCS = main.c dns.c


all: $(NAME)

$(NAME): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(NAME)

clean:
	rm -f $(NAME)

do: $(NAME)
	./$(NAME)

server: server.c
	gcc -O3 -Wall server.c -o server
