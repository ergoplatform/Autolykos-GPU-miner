.SUFFIXES:
.SUFFIXES: .cc .c .cu .o

# load options
include Makefile.in

# set shell
SHELL := /bin/bash

# compiler standard
STD = --std=c++11

# side libs paths
LIBS = -L/usr/local/lib -lcurl -I/usr/local/include -lssl -lcrypto -lnvidia-ml

# stub config content
CONFIG = '{ \
			 "mnemonic": "do not disclose the secret seed", \
			 "node": "http://188.166.89.71:9052", \
			 "keepPrehash": false \
		 }'

# compiler settings
CXX = nvcc
CFLAGS = -c --compiler-options -Wall
CXXFLAGS = -c $(STD) --compiler-options -Wall
COPT = -O3

# find CUDA compute capability
SMS ?= $(shell nvcc -h | grep "compute" | sed -e "s/['=, \d40\d41]/\n/g" \
	   | grep compute | sort | uniq | cut -c 9-)

ifeq ($(GENCODE_FLAGS),)
### useful ### $(foreach sm,$(SMS),\
### useful ### $(eval GENCODE_FLAGS += -gencode arch=compute_$(sm),code=sm_$(sm)))
HIGHEST_SM = $(strip $(lastword $(SMS)))
ifneq ($(HIGHEST_SM),)
GENCODE_FLAGS += -gencode arch=compute_$(CUDAARCH),code=sm_$(CUDAARCH) \
	-gencode arch=compute_$(HIGHEST_SM),code=compute_$(HIGHEST_SM) \
	-gencode arch=compute_30,code=compute_30  # default arch for compatibility
endif
endif

### NOTE: code=sm_xx means cuda binary generation for xx arch, 
### code=compute_xx - PTX generation, PTX for compute_30 is compatible 
### with higher arches, but binary is not

# lib
AR = ar
LIBPATH = ./lib/lib.a

SRCDIR = ./src

# define sources
CUSOURCES = $(filter-out $(SRCDIR)/test.cu $(SRCDIR)/autolykos.cu, \
			$(wildcard $(SRCDIR)/*.cu))
CPPSOURCES = $(wildcard $(SRCDIR)/*.cc) $(wildcard $(SRCDIR)/bip39/*.cc)
CSOURCES = $(wildcard $(SRCDIR)/*.c)

# define objects
OBJECTS = $(CUSOURCES:.cu=.o) $(CPPSOURCES:.cc=.o) $(CSOURCES:.c=.o)

# define executables
AUTOEXEC = auto.out
TESTEXEC = test.out

# compile objects
%.o: %.cu
	$(CXX) $(COPT) $(CXXFLAGS) $(GENCODE_FLAGS) --maxrregcount $(MAXREG) \
		-DBLOCK_DIM=$(BLOCKDIM) -DNONCES_PER_ITER=$(WORKSPACE) $< -o $@
%.o: %.cc
	$(CXX) $(COPT) $(CXXFLAGS) $(EMBED) $< -o $@
%.o: %.c
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

# default (miner executable)
all: clean lib autoexec
	@if ! [ -e "config.json" ]; then \
		echo $(CONFIG) > config.json; \
		echo "Stub config.json was generated"; \
	fi

# test executable
test: clean lib testexec 

# lib
lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

# miner executable if lib made
autoexec:
	$(CXX) $(SRCDIR)/autolykos.cu $(LIBPATH) $(LIBS) $(COPT) $(STD) \
		$(GENCODE_FLAGS) -DBLOCK_DIM=$(BLOCKDIM) \
		-DNONCES_PER_ITER=$(WORKSPACE) -o $(AUTOEXEC)

# test executable if lib made
testexec: 
	$(CXX) $(SRCDIR)/test.cu $(LIBPATH) $(LIBS) $(COPT) $(STD) \
		$(GENCODE_FLAGS) -DBLOCK_DIM=$(BLOCKDIM) \
		-DNONCES_PER_ITER=$(WORKSPACE) -o $(TESTEXEC)

# kill them all
clean:
	rm -f $(OBJECTS) $(SRCDIR)/autolykos.o $(SRCDIR)/test.o $(LIBPATH) \
		$(TESTEXEC) $(AUTOEXEC)

.PHONY: all autoexec clean lib test testexec
