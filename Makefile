
CC=gcc

ifdef RELEASE
COPTS=-std=c99 -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual \
        -Wstrict-prototypes -Wmissing-prototypes
COPTS+=-O2
else
COPTS=-std=c99 -pedantic -Wall \
    -Wextra  -Wformat=2 -Wswitch-default -Wswitch-enum -Wcast-align -Wpointer-arith \
    -Wbad-function-cast -Wstrict-overflow=5 -Wstrict-prototypes -Winline \
    -Wundef -Wnested-externs -Wcast-qual -Wshadow  \
    -Wfloat-equal -Wstrict-aliasing=2 -Wredundant-decls \
    -Wold-style-definition -Werror

COPTS+=-g -O0 -fno-omit-frame-pointer  -fno-common -fstrict-aliasing
endif

CFLAGS=-I dist/cjson $(COPTS)
LDFLAGS=  -lssh -lcurl

stunneler: src/stunneler.o dist/cjson/cJSON.o
	$(CC) -o stunneler src/stunneler.o dist/cjson/cJSON.o $(LDFLAGS)

clean:
	rm -rf src/*.o dist/cjson/*.o
