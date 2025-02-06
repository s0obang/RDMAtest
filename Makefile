all: client server

server: server.o common.o
	gcc -o server server.o common.o -libverbs -lrdmacm

client: client.o common.o
	gcc -o client client.o common.o -libverbs -lrdmacm

server.o: server.c common.h
	gcc -c server.c

client.o: client.c common.h
	gcc -c client.c

common.o: common.c common.h
	gcc -c common.c

clean:
	rm -f *.o server client
