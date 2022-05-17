CFLAGS = -Wall -Wpedantic -I./3rdparty

CFLAGS += $(shell pkg-config --static --cflags yara libcrypto)
LIBS   += $(shell pkg-config --static --libs yara libcrypto)

all: gimphash

gimphash: gimphash.o
	$(CC) -static -o $@ $^ $(LIBS) 

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f gimphash *.o

.PHONY: all clean
