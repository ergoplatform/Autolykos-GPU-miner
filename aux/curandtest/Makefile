.SUFFIXES:
.SUFFIXES: .cu .o

include Makefile.in

CFLAGS = -c

SRCDIR = .
SOURCES = $(SRCDIR)/randtest.cu
OBJECTS = $(SOURCES:.cu=.o)

LIBPATH = ./lib/$(LIBNAME)

TESTEXEC = test.out

.cu.o:
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

all: clean lib test

lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

test:
	$(CXX) $(LIBPATH) $(LIBS) $(COPT) -o $(TESTEXEC)

clean:
	rm -f $(OBJECTS) $(LIBPATH) $(TESTEXEC)
