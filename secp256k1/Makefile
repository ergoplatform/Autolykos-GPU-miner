.SUFFIXES:
.SUFFIXES: .cc .c .cu .o

# load options
include Makefile.in

# set shell
SHELL := /bin/bash

# compiler 
CXX = nvcc
CFLAGS = -c
CXXFLAGS = -c $(STD)
COPT = -O3

# find CUDA compute capability
SMS ?= $(shell nvcc -h | grep "compute" | sed -e "s/['=, \d40\d41]/\n/g" \
	   | grep compute | sort | uniq | cut -c 9-)

ifeq ($(GENCODE_FLAGS),)
### useful ### $(foreach sm,$(SMS),\
### useful ### $(eval GENCODE_FLAGS += -gencode arch=compute_$(sm),code=sm_$(sm)))
HIGHEST_SM = $(strip $(lastword $(SMS)))
ifneq ($(HIGHEST_SM),)
GENCODE_FLAGS += -arch=sm_$(CUDAARCH) \
	-gencode arch=compute_$(HIGHEST_SM),code=compute_$(HIGHEST_SM)
endif
endif

# define assembly
AR = ar
SRCDIR = ./src
LIBPATH = ./lib/lib.a

# define sources
CUSOURCES = $(filter-out $(SRCDIR)/autolykos.cu, $(wildcard $(SRCDIR)/*.cu))
CPPSOURCES = $(wildcard $(SRCDIR)/*.cc)
CSOURCES = $(wildcard $(SRCDIR)/*.c)

# define objects
OBJECTS = $(CUSOURCES:.cu=.o) $(CPPSOURCES:.cc=.o) $(CSOURCES:.c=.o)

# define executable
AUTOEXEC = auto.out

# compile objects
%.o: %.cu
	$(CXX) $(COPT) $(CXXFLAGS) $(GENCODE_FLAGS) $< -o $@
%.o: %.cc
	$(CXX) $(COPT) $(CXXFLAGS) $< -o $@
%.o: %.c
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

all: clean lib auto
	@if ! [ -e "config.json" ]; then \
		echo $(CONFIG) > config.json; \
		echo "Stub config.json was generated"; \
	fi

lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

auto:
	$(CXX) $(SRCDIR)/autolykos.cu $(LIBPATH) $(LIBS) $(COPT) $(STD) \
		$(GENCODE_FLAGS) -o $(AUTOEXEC)

clean:
	rm -f $(OBJECTS) $(SRCDIR)/autolykos.o $(LIBPATH) $(TESTEXEC) $(AUTOEXEC)

.PHONY: all clean auto lib
