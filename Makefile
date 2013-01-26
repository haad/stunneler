
CC=gcc

CWARN=-std=c99 -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual \
        -Wstrict-prototypes -Wmissing-prototypes
COPTS=-O2
CDEB=-g

CFLAGS=-I dist/cjson $(COPTS) $(CDEB) $(CWARN)

stunneler: src/stunneler.o dist/cjson/cJSON.o
	$(CC) -o stunneler src/stunneler.o dist/cjson/cJSON.o

clean:
	rm -rf src/*.o dist/cjson/*.o
