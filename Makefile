SOURCES= ./hopfake.c

DESTS= $(SOURCES:.c=)
CC= cc

DEBUG    = #-DDEBUG
CFLAG    = -Wall
LIBS     = -lpcap

ALLOPT   = $(DEBUG) $(CFLAGS)

.c:
	$(CC) $(ALLOPT) $(DEFS) $< $(LIBS) -o $@

all: $(DESTS)

clean:
	@rm -rf core $(DESTS) 

