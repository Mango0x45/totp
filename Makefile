CC = cc
CFLAGS = -Wall -Wextra -Wpedantic -Werror \
         -O3 -march=native -mtune=native \
         -fomit-frame-pointer -pipe
LDLIBS = -luriparser -lssl -lcrypto

PREFIX  = /usr/local
DPREFIX = ${DESTDIR}${PREFIX}

all: totp
totp: main.o b32.o
	${CC} ${LDLIBS} -o $@ main.o b32.o

main.o: main.c b32.h
	${CC} ${CFLAGS} -c main.c

b32.o: b32.c b32.h
	${CC} ${CFLAGS} -c b32.c

install:
	mkdir -p ${DPREFIX}/bin ${DPREFIX}/share/man/man1
	cp totp ${DPREFIX}/bin
	cp totp.1 ${DPREFIX}/share/man/man1

clean:
	rm -f totp *.o
