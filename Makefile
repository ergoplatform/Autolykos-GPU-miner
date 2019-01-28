.SUFFIXES:
.SUFFIXES: .cu .o

include Makefile.in

CFLAGS = -c

SRCDIR = .
SOURCES = $(SRCDIR)/kerneltest.cu $(SRCDIR)/blake2b.cu $(SRCDIR)/kernel.cu \
		  $(SRCDIR)/autolykos.cu $(SRCDIR)/main.cu
OBJECTS = $(SOURCES:.cu=.o)

LIBPATH = ./lib/$(LIBNAME)

TESTEXEC = test.out
AUTOEXEC = auto.out

.cu.o:
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

test:
	$(CXX) $(LIBPATH) $(COPT) -o $(TESTEXEC)

auto:
	$(CXX) $(LIBPATH) $(COPT) -o $(AUTOEXEC)

clean:
	rm -f $(OBJECTS) $(LIBPATH) $(TESTEXEC) $(AUTOEXEC)
