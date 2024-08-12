build: main.c
	echo "Building project..."
	gcc -Wall -o main.out main.c

debug: main.c
	echo "Building debug version..."
	gcc -Wall -g -o debug.out main.c

clean:
	rm -f *.out
