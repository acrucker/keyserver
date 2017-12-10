all: main

main: *.c *.h
	clang -g --std=gnu89 -o main *.c -Wall -Werror -lcrypto -ldb -lulfius -lpthread -D_DEFAULT_SOURCE -D_GNU_SOURCE -O3

clean: 
	rm main test.db
