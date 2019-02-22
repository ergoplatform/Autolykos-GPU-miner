.SUFFIXES:
.SUFFIXES: .cu .o

include Makefile.in

CFLAGS = -c -arch sm_70 #-Xptxas -v

SRCDIR = ./src
LIBPATH = ./lib/$(LIBNAME)
SOURCES = $(SRCDIR)/reduction.cu $(SRCDIR)/compaction.cu \
		  $(SRCDIR)/prehash.cu $(SRCDIR)/mining.cu \
		  $(SRCDIR)/autolykos.cu
OBJECTS = $(SOURCES:.cu=.o)

TESTEXEC = test.out
AUTOEXEC = auto.out

.cu.o:
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

all: clean lib test

lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

test:
	$(CXX) $(LIBPATH) $(LIBS) $(COPT) -o $(TESTEXEC)

auto:
	$(CXX) $(LIBPATH) $(LIBS) $(COPT) -o $(AUTOEXEC)

clean:
	rm -f $(OBJECTS) $(LIBPATH) $(TESTEXEC) $(AUTOEXEC)
