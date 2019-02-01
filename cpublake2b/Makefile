.SUFFIXES:
.SUFFIXES: .c .o

include Makefile.in

CFLAGS = -c

SRCDIR = .
LIBPATH = ./lib/$(LIBNAME)

SOURCES = $(SRCDIR)/test.c $(SRCDIR)/blake2b.c $(SRCDIR)/kernel.c
OBJECTS = $(SOURCES:.c=.o)

TESTEXEC = test.out

.c.o:
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

all: clean lib test

lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

test:
	$(CXX) $(LIBPATH) $(COPT) -o $(TESTEXEC)

clean:
	rm -f $(OBJECTS) $(LIBPATH) $(TESTEXEC)
