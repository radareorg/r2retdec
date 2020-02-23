# RetDec r2plugin sources.
set(SOURCES
	core_plugin.cpp
	r2info.cpp
	r2utils.cpp
	r2cgen.cpp
)

add_library(core_retdec SHARED ${SOURCES})

target_link_libraries(core_retdec
	Radare2::libr
	retdec
	rapidjson
	annotations
	stdc++fs
)

target_include_directories(core_retdec PUBLIC ${PROJECT_SOURCE_DIR}/include/)

set_target_properties(core_retdec PROPERTIES
	OUTPUT_NAME core_retdec
	PREFIX ""
)

target_compile_definitions(core_retdec PRIVATE "-DRETDEC_INSTALL_PREFIX=\"${RETDEC_INSTALL_PREFIX}\"")

install(TARGETS core_retdec DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
