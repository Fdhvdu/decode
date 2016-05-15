cmake_minimum_required(VERSION 3.5.1)

include(ExternalProject)
ExternalProject_Add(cryptopp
	GIT_REPOSITORY https://github.com/weidai11/cryptopp.git
	GIT_TAG CRYPTOPP_8_1_0
	PREFIX cryptopp
	CONFIGURE_COMMAND ""	# no configure
	BUILD_COMMAND make -j
	BUILD_IN_SOURCE 1
	INSTALL_COMMAND make -j install PREFIX=<INSTALL_DIR>
)

set(CMAKE_CXX_STANDARD 14)

ExternalProject_Get_Property(cryptopp INSTALL_DIR)

include_directories(${INSTALL_DIR}/include)
add_executable(decode main.cpp)
target_link_libraries(decode ${INSTALL_DIR}/lib/libcryptopp.a)
