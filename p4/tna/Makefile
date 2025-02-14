NF             := peregrine.p4
P4C            := $(SDE_INSTALL)/bin/bf-p4c
DEBUG_FLAGS    := -g --verbose 2 --create-graphs
MKDIR          := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR      := $(MKDIR)/build
INSTALL_SCRIPT  = $(MKDIR)/../p4_build.sh

debug: $(NF)
	$(P4C) $(DEBUG_FLAGS) -o $(BUILD_DIR) $(NF)

install: $(NF)
	$(INSTALL_SCRIPT) $(NF)

.PHONY: clean

clean:
	rm -rf build
