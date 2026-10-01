NF			   := peregrine.p4
ARCH		   := P4_ARCHITECTURE=tna P4_VERSION=p4_16
P4C			   := $(SDE_INSTALL)/bin/bf-p4c
# DEBUG_FLAGS    := -g --verbose 2 -Xp4c="--disable-parse-depth-limit"
# DEBUG_FLAGS    := -g
MKDIR		   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR	   := $(MKDIR)/build
INSTALL_SCRIPT	= $(MKDIR)/../../../build_tools/p4_build.sh
debug: $(NF)
	$(P4C) $(DEBUG_FLAGS) -o $(BUILD_DIR) $(NF)

install: $(NF)
	$(INSTALL_SCRIPT) $(NF) $(ARCH) -- $(DEBUG_FLAGS)


.PHONY: clean

clean:
	rm -rf build
