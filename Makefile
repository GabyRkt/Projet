CFLAGS = -g -Wall -lm -Wextra -pedantic 
CC = gcc

PROGRAMS = mainCrypto calcul mainSecure mainCentrale mainDecentrale

.PHONY:	all clean

all: $(PROGRAMS)

mainCrypto: mainCrypto.o  crypto.o -lm
	$(CC) -o $@ $(CFLAGS) $^ 

mainSecure: mainSecure.o  secure.o crypto.o -lm
	$(CC) -o $@ $(CFLAGS) $^ 

mainCentrale: mainCentrale.o centrale.o secure.o crypto.o -lm
	$(CC) -o $@ $(CFLAGS) $^

mainDecentrale: mainDecentrale.o decentrale.o centrale.o secure.o crypto.o -lm -lssl -lcrypto
	$(CC) -o $@ $(CFLAGS) $^

calcul: calcul.o  crypto.o -lm
	$(CC) -o $@ $(CFLAGS) $^

crypto.o: crypto.c
	$(CC) -c $(CFLAGS) crypto.c 

secure.o: secure.c 
	$(CC) -c $(CFLAGS) secure.c 

centrale.o: centrale.c 
	$(CC) -c $(CFLAGS) centrale.c 

decentrale.o: decentrale.c 
	$(CC) -c $(CFLAGS) decentrale.c 


clean:
	rm -f *.o *~ $(PROGRAMS)
