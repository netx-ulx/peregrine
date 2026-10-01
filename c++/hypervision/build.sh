#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_DIR="$SCRIPT_DIR/build"
RELEASE_DIR="$BUILD_DIR/release"
DEBUG_DIR="$BUILD_DIR/debug"

mkdir -p $RELEASE_DIR
mkdir -p $DEBUG_DIR

pushd $RELEASE_DIR > /dev/null
	cmake -DCMAKE_BUILD_TYPE=Release ../..
	make -j
popd > /dev/null

pushd $DEBUG_DIR > /dev/null
	cmake -DCMAKE_BUILD_TYPE=Debug ../..
	make -j
popd > /dev/null

ln -sf build/release/compile_commands.json compile_commands.json
