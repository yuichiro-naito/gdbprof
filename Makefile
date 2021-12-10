SRCS=gdbprof.c
CFLAGS+=-Wall -g

gdbprof: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f gdbprof
