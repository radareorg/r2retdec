cmake_minimum_required(VERSION 3.12)

project(r2retdec)

set(RADARE2_INSTALL_PLUGDIR "share/radare2/plugins" CACHE PATH "Directory to install radare2 plugin into")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 11)

set(SOURCE src/core_retdec.cpp)

find_package(Radare2 REQUIRED)

add_library(core_retdec SHARED ${SOURCE})
target_link_libraries(core_retdec Radare2::libr)
set_target_properties(core_retdec PROPERTIES
		OUTPUT_NAME core_retdec
		PREFIX "")

install(TARGETS core_retdec DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
