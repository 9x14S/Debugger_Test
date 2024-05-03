.PHONY: all clean test

all: debugger.c
	gcc -o sdb debugger.c -lcapstone -Wall -Wextra -Wunused 
	./sdb ./t

test: ctests.c
	gcc -o t ctests.c -Wall

clean: 
	rm t sdb -f 
