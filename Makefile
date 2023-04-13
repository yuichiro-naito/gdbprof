CFLAGS+=-Wall -g

all: gdbprof gdbbt

gdbbt: gdbbt.c
	$(CC) $(CFLAGS) -o $@ gdbbt.c

gdbprof: $(SRCS)
	$(CC) $(CFLAGS) -o $@ gdbprof.c

clean:
	rm -f gdbprof gdbbt
