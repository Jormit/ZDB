debugger: debugger.c main.c elf-parser.c
	clang -o debugger debugger.c main.c elf-parser.c -lcapstone

