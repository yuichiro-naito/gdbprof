SRCS=gdbprof.c
CLFAGS+=-Wall

gdbprof: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f gdbprof
