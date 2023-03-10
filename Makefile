CC = clang

CFLAGS = -Wall -Wextra -Werror -pedantic

all: httpserver

httpserver: httpserver.o
	$(CC) httpserver.o -o httpserver helper_funcs.a


clean:
	rm -f httpserver *.o
