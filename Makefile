CC = clang
CFLAGS = -Wall -Werror -Wextra -Wpedantic $(shell pkg-config --cflags gmp)
LFLAGS = $(shell pkg-config --libs gmp) -lm

all: encrypt decrypt keygen

encrypt: encrypt.o
	$(CC) -o encrypt encrypt.o randstate.o numtheory.o rsa.o $(LFLAGS)

encrypt.o: encrypt.c randstate.c numtheory.c rsa.c
	$(CC) $(CFLAGS) -c encrypt.c randstate.c numtheory.c rsa.c

decrypt: decrypt.o
	$(CC) -o decrypt decrypt.o randstate.o numtheory.o rsa.o $(LFLAGS)

decrypt.o: decrypt.c randstate.c numtheory.c rsa.c
	$(CC) $(CFLAGS) -c decrypt.c randstate.c numtheory.c rsa.c 

keygen: keygen.o
	$(CC) -o keygen keygen.o randstate.o numtheory.o rsa.o $(LFLAGS)

keygen.o: keygen.c randstate.c numtheory.c rsa.c
	$(CC) $(CFLAGS) -c keygen.c randstate.c numtheory.c rsa.c

debug: CFLAGS += -g
debug: all

clean:
	rm -f encrypt decrypt keygen encrypt.o decrypt.o keygen.o *.o *.pub *.priv

format:
	clang-format -i -style=file *.[ch]
