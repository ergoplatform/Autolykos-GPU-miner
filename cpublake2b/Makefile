.SUFFIXES:
.SUFFIXES: .c .o

include Makefile.in

CFLAGS = -c

SRCDIR = .
SOURCES = $(SRCDIR)/test.c $(SRCDIR)/blake2b.c $(SRCDIR)/kernel.c
OBJECTS = $(SOURCES:.c=.o)

LIBPATH = ./lib/$(LIBNAME)

TESTEXEC = test.out

.c.o:
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

test:
	$(CXX) $(LIBPATH) $(COPT) -o $(TESTEXEC)

clean:
	rm -f $(OBJECTS) $(LIBPATH) $(TESTEXEC)
