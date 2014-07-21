
all:	main

main:	main.c
	gcc -g -o main main.c

test:	main
	./main in.test
	sha256sum in.test

