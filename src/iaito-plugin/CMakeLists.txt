if (NOT BUILD_BUNDLED_RETDEC)
	set(RETDEC_VERSION 4.0)
	find_package(retdec ${RETDEC_VERSION} REQUIRED COMPONENTS retdec config)
endif()

set(IAITO_PLUGIN_INCLUDE ${PROJECT_SOURCE_DIR}/include/iaito-plugin)

set(SOURCE
	${IAITO_PLUGIN_INCLUDE}/core_plugin.h
	core_plugin.cpp
)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt5 REQUIRED COMPONENTS Widgets)

add_library(r2retdec_iaito SHARED ${SOURCE})

get_property(CORE_LIBS GLOBAL PROPERTY R2RETDEC_CORE_LIBS)

target_link_libraries(r2retdec_iaito
	${CORE_LIBS}
	Qt5::Widgets
	Radare2::libr
	Iaito::Iaito
)

target_include_directories(r2retdec_iaito PUBLIC ${PROJECT_SOURCE_DIR}/include/)

if(APPLE)
	target_link_options(r2retdec_iaito PRIVATE -undefined dynamic_lookup)

elseif(WIN32)
	target_link_options(r2retdec_iaito PRIVATE -FORCE:UNRESOLVED)
endif()

install(TARGETS r2retdec_iaito DESTINATION "${IAITO_INSTALL_PLUGDIR}")
