all: packet.c
	gcc -o packet packet.c -lpcap -pthread
