# RetDec r2plugin sources.
set(
	SOURCE
	core_plugin.cpp
	r2info.cpp
	r2utils.cpp
	r2cgen.cpp
)

add_library(core_retdec SHARED ${SOURCE})

target_link_libraries(core_retdec Radare2::libr retdec jsoncpp r2annotations)
set_target_properties(core_retdec PROPERTIES
		OUTPUT_NAME core_retdec
		PREFIX "")

target_compile_definitions(core_retdec PRIVATE "-DRETDEC_CUSTOM_INSTALL=\"${RETDEC_CUSTOM_INSTALL}\"")

install(TARGETS core_retdec DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
