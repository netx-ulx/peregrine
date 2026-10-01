NF             := peregrine.p4
ARCH 		   := P4_ARCHITECTURE=t2na
P4C            := $(SDE_INSTALL)/bin/bf-p4c
DEBUG_FLAGS    := -g --verbose 2 --create-graphs -b tofino2
MKDIR          := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR      := $(MKDIR)/build
INSTALL_SCRIPT  = $(MKDIR)/../../../build_tools/p4_build.sh

debug: $(NF)
	$(P4C) $(DEBUG_FLAGS) -o $(BUILD_DIR) $(NF)

install: $(NF)
	$(INSTALL_SCRIPT) $(NF) $(ARCH)

.PHONY: clean

clean:
	rm -rf build
