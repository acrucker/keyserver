all: main

main: *.c *.h
	gcc -g --std=c89 -o main *.c -Wall -Werror -lcrypto -ldb -D_DEFAULT_SOURCE

clean: 
	rm main
