all: main

main: *.c *.h
	gcc -g --std=gnu89 -o main *.c -Wall -Werror -lcrypto -ldb -lulfius -D_DEFAULT_SOURCE

clean: 
	rm main test.db
