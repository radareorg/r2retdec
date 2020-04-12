if (BUILD_BUNDLED_RETDEC)
	retdec_install()
else ()
	retdec_install_config()
endif ()

find_package(retdec REQUIRED COMPONENTS config)

# RetDec r2plugin sources.
set(SOURCES
	core_plugin.cpp
	cmd_exec.cpp
	r2info.cpp
	r2utils.cpp
	r2cgen.cpp
)

add_library(core_retdec SHARED ${SOURCES})

target_link_libraries(core_retdec
	Radare2::libr
	retdec::config
	rapidjson
	annotations
)

find_library(STD_CPP_FS stdc++fs)
if (STD_CPP_FS)
	message("-- Linking with ${STD_CPP_FS} library")
	target_link_libraries(core_retdec
		stdc++fs
	)
else()
	message("-- Library stdc++fs NOT FOUND -> linking core_retdec without stdc++fs library")
endif()

target_include_directories(core_retdec PUBLIC ${PROJECT_SOURCE_DIR}/include/)

set_target_properties(core_retdec PROPERTIES
	OUTPUT_NAME core_retdec
	PREFIX ""
)

target_compile_definitions(core_retdec PRIVATE "-DRETDEC_INSTALL_PREFIX=\"${RETDEC_INSTALL_PREFIX}\"")

install(TARGETS core_retdec DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
