build: main.c display.c
	echo "Building project..."
	gcc -Wall -o main.out main.c display.c

debug: main.c display.c
	echo "Building debug version..."
	gcc -Wall -Wextra -Wconversion -g -o debug.out main.c display.c

clean:
	rm -f *.out
