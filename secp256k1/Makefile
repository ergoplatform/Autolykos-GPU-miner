.SUFFIXES:
.SUFFIXES: .c .cu .o

include Makefile.in

SMS ?= 75 #30 35 37 50 52 53 60 62 61 70

ifeq ($(GENCODE_FLAGS),)
$(foreach sm,$(SMS),\
$(eval GENCODE_FLAGS += -gencode arch=compute_$(sm),code=sm_$(sm)))

HIGHEST_SM := $(strip $(lastword $(sort $(SMS))))
ifneq ($(HIGHEST_SM),)
GENCODE_FLAGS += -arch=sm_30 \
	-gencode arch=compute_$(HIGHEST_SM),code=compute_$(HIGHEST_SM)
endif
endif

CFLAGS = -c

SRCDIR = ./src
LIBPATH = ./lib/$(LIBNAME)
CUSOURCES = $(filter-out $(SRCDIR)/test.cu $(SRCDIR)/autolykos.cu, \
			$(wildcard $(SRCDIR)/*.cu))
CSOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(CUSOURCES:.cu=.o) $(CSOURCES:.c=.o)

$(info $(OBJECTS))

TESTEXEC = test.out
AUTOEXEC = auto.out

%.o: %.cu
	$(CXX) $(COPT) $(CFLAGS) $(GENCODE_FLAGS) $< -o $@
%.o: %.c
	$(CXX) $(COPT) $(CFLAGS) $< -o $@
###%jsmn.o: %jsmn.c
###	$(CXX) $(COPT) $(CFLAGS) $< -o $@

all: clean lib test

lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

test:
	$(CXX) $(SRCDIR)/test.cu $(LIBPATH) $(LIBS) $(COPT) $(GENCODE_FLAGS) \
	-o $(TESTEXEC)

auto:
	$(CXX) $(SRCDIR)/autolykos.cu $(LIBPATH) $(LIBS) $(COPT) $(GENCODE_FLAGS) \
	-o $(AUTOEXEC)

clean:
	rm -f $(OBJECTS) $(SRCDIR)/test.o $(SRCDIR)/autolykos.o $(LIBPATH) \
	$(TESTEXEC) $(AUTOEXEC)

.PHONY: all clean test auto lib
