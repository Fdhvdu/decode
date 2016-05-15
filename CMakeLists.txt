cmake_minimum_required(VERSION 3.6)

include(ProcessorCount)
ProcessorCount(N)

include(ExternalProject)
ExternalProject_Add(cryptopp
	GIT_REPOSITORY https://github.com/weidai11/cryptopp.git
	GIT_TAG CRYPTOPP_8_7_0
	GIT_SHALLOW 1
	PREFIX cryptopp
	CONFIGURE_COMMAND ""	# no configure
	BUILD_COMMAND make -j ${N}
	BUILD_IN_SOURCE 1
	BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/cryptopp/lib/libcryptopp.a
	INSTALL_COMMAND make -j install PREFIX=<INSTALL_DIR>
)

set(CMAKE_CXX_STANDARD 17)

ExternalProject_Get_Property(cryptopp INSTALL_DIR)

include_directories(${INSTALL_DIR}/include)
add_executable(decode main.cpp)
add_dependencies(decode cryptopp)
target_link_libraries(decode ${INSTALL_DIR}/lib/libcryptopp.a)
