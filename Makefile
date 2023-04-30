debugger: debugger.c main.c elf-parser.c test
	clang -o debugger debugger.c main.c elf-parser.c -lcapstone -Wall

test: test.c
	clang -o test test.c
