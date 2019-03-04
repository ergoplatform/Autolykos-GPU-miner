.SUFFIXES:
.SUFFIXES: .cu .o

include Makefile.in

SMS ?= 30 35 37 50 52 53 60 62 61 70

ifeq ($(GENCODE_FLAGS),)                                                         
$(foreach sm,$(SMS),\
$(eval GENCODE_FLAGS += -gencode arch=compute_$(sm),code=sm_$(sm)))
																				 
HIGHEST_SM := $(strip $(lastword $(sort $(SMS))))
ifneq ($(HIGHEST_SM),)                                                           
GENCODE_FLAGS += -arch=sm_30 -gencode arch=compute_$(HIGHEST_SM),code=compute_$(HIGHEST_SM)
endif                                                                            
endif                                                   

CFLAGS = -c 

SRCDIR = ./src
LIBPATH = ./lib/$(LIBNAME)
SOURCES = $(SRCDIR)/reduction.cu $(SRCDIR)/compaction.cu \
		  $(SRCDIR)/prehash.cu $(SRCDIR)/mining.cu \
		  $(SRCDIR)/autolykos.cu
OBJECTS = $(SOURCES:.cu=.o)

TESTEXEC = test.out
AUTOEXEC = auto.out

.cu.o:
	$(CXX) $(COPT) $(CFLAGS) $(GENCODE_FLAGS) $< -o $@

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
