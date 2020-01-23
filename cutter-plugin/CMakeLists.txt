# This file originated from cuuter-plugin/CMakeLists.txt located
# in https://github.com/radareorg/r2ghidra-dec project under LGPLv3 license.

set(SOURCE
		R2RetDecPlugin.h
		R2RetDecPlugin.cpp
		R2RetDec.h
		R2RetDec.cpp)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt5 REQUIRED COMPONENTS Widgets)

add_library(r2retdec_cutter SHARED ${SOURCE})
target_link_libraries(r2retdec_cutter Qt5::Widgets)
target_link_libraries(r2retdec_cutter Radare2::libr)

find_package(Cutter REQUIRED)
target_link_libraries(r2retdec_cutter Cutter::Cutter)

if(APPLE)
	target_link_options(r2retdec_cutter PRIVATE -undefined dynamic_lookup)
endif()

if(WIN32)
	target_link_options(r2retdec_cutter PRIVATE -FORCE:UNRESOLVED)
endif()

install(TARGETS r2retdec_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
