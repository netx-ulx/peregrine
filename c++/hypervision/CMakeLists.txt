cmake_minimum_required(VERSION 3.16)
project(hypervision)

###############################################################################
# C++ standard version
###############################################################################

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

###############################################################################
# Compilation flags
###############################################################################

add_compile_options(
	-Wall -Wextra -Werror -Wfatal-errors
	-Wno-unused-variable -Wno-unused-parameter
)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

set(CFLAGS "-fopenmp")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CFLAGS}")

###############################################################################
# Variables
###############################################################################

set(PROG "hypervision")
set(CUR_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(SRC_DIR "${CUR_DIR}/src")

###############################################################################
# Output targets
###############################################################################

file(GLOB_RECURSE SOURCES "${SRC_DIR}/*.cpp")
file(GLOB_RECURSE HEADERS "${SRC_DIR}/*.h")

add_executable(${PROG} ${SOURCES})

###############################################################################
# External projects
###############################################################################

include(${CMAKE_SOURCE_DIR}/cmake/find_json.cmake)
find_package(OpenMP)

target_link_libraries(${PROG}
	nlohmann_json::nlohmann_json
	libPcap++.a
	libPacket++.a
	libCommon++.a
	pcap
	pthread
	OpenMP::OpenMP_CXX
	armadillo
	mlpack
	z3
)
