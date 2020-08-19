
set(CUTTER_PLUGIN_INCLUDE ${PROJECT_SOURCE_DIR}/include/cutter-plugin)

set(SOURCE
	${CUTTER_PLUGIN_INCLUDE}/core_plugin.h
	core_plugin.cpp
)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt5 REQUIRED COMPONENTS Widgets)

add_library(r2retdec_cutter SHARED ${SOURCE})

target_link_libraries(r2retdec_cutter
	Qt5::Widgets
	Radare2::libr
	Cutter::Cutter
	core_retdec
)

target_include_directories(r2retdec_cutter PUBLIC ${PROJECT_SOURCE_DIR}/include/)

if(APPLE)
	target_link_options(r2retdec_cutter PRIVATE -undefined dynamic_lookup)

elseif(WIN32)
	target_link_options(r2retdec_cutter PRIVATE -FORCE:UNRESOLVED)
endif()

install(TARGETS r2retdec_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
