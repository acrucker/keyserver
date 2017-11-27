all: main ingest

main: main.c ibf.c *.h
	gcc -g --std=c89 -o main main.c ibf.c -Wall -Werror

ingest: ingest.c key.c *.h
	gcc -g --std=c89 -o ingest ingest.c key.c  -Wall -Werror
