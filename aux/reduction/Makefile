.SUFFIXES:
.SUFFIXES: .cu .o

include Makefile.in

CFLAGS = -c

SRCDIR = .
LIBPATH = ./lib/$(LIBNAME)

SOURCES = $(SRCDIR)/reductiontest.cu
OBJECTS = $(SOURCES:.cu=.o)

TESTEXEC = test.out

.cu.o:
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
