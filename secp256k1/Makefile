.SUFFIXES:
.SUFFIXES: .cc .c .cu .o

include Makefile.in

SHELL := /bin/bash

SMS ?= $(shell nvcc -h | grep "compute" | sed -e "s/['=, \d40\d41]/\n/g" \
	   | grep compute | sort | uniq | cut -c 9-)

ifeq ($(GENCODE_FLAGS),)
#$(foreach sm,$(SMS),\
#$(eval GENCODE_FLAGS += -gencode arch=compute_$(sm),code=sm_$(sm)))
HIGHEST_SM = $(strip $(lastword $(sort $(SMS))))
ifneq ($(HIGHEST_SM),)
GENCODE_FLAGS += -arch=sm_30 \
	-gencode arch=compute_$(HIGHEST_SM),code=compute_$(HIGHEST_SM)
endif
endif

CFLAGS = -c

SRCDIR = ./src
LIBPATH = ./lib/$(LIBNAME)
CUSOURCES = $(filter-out $(SRCDIR)/autolykos.cu, $(wildcard $(SRCDIR)/*.cu))
CPPSOURCES = $(wildcard $(SRCDIR)/*.cc)
CSOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(CUSOURCES:.cu=.o) $(CPPSOURCES:.cc=.o) $(CSOURCES:.c=.o)

AUTOEXEC = auto.out

%.o: %.cu
	$(CXX) $(COPT) $(CFLAGS) $(GENCODE_FLAGS) $< -o $@
%.o: %.cc
	$(CXX) $(COPT) $(CFLAGS) --std=c++11 $< -o $@
%.o: %.c
	$(CXX) $(COPT) $(CFLAGS) $< -o $@
###%jsmn.o: %jsmn.c
###	$(CXX) $(COPT) $(CFLAGS) $< -o $@

CONFIG = '{ \
			 "seed": "do not disclose the secret seed", \
			 "node": "http://188.166.89.71:9052", \
			 "keepPrehash": false \
		 }'

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
	$(CXX) $(SRCDIR)/autolykos.cu --std=c++11 $(LIBPATH) $(LIBS) $(COPT) $(GENCODE_FLAGS) \
		-o $(AUTOEXEC)

clean:
	rm -f $(OBJECTS) $(SRCDIR)/autolykos.o $(LIBPATH) $(TESTEXEC) $(AUTOEXEC)

.PHONY: all clean auto lib
