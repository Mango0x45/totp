CC = cc
CFLAGS = -g
LDLIBS = -luriparser -lssl -lcrypto

all: totp
totp: main.o b32.o
	${CC} ${LDLIBS} -o $@ main.o b32.o

main.o: main.c b32.h
	${CC} ${CFLAGS} -c main.c

b32.o: b32.c b32.h
	${CC} ${CFLAGS} -c b32.c

clean:
	rm -f totp *.o
