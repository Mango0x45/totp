CC = cc
CFLAGS = \
	-Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align \
	-Wwrite-strings -Wmissing-prototypes -Wmissing-declarations \
	-Wredundant-decls -Wnested-externs -Winline -Wno-long-long \
	-Wconversion -Wstrict-prototypes \
	-O3 -march=native -mtune=native -pipe
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
