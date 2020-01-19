include(ExternalProject)

ExternalProject_Add(r2ghidra
	URL https://github.com/radareorg/r2ghidra-dec/archive/a7c2fe22a41231edb51b9794a7686e54c5edc3fe.zip
	URL_HASH SHA256=96dbb35dd1a6219c3208bd1c13a71d15fede6382b86f536a18339c1663416555
	# Disable the configure step.
        CONFIGURE_COMMAND ""	
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the build step.
	BUILD_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

# Set include directories.
ExternalProject_Get_Property(r2ghidra source_dir)
ExternalProject_Get_Property(r2ghidra binary_dir)

set(ANNOTATED_CODE_SOURCES
	${source_dir}/src/AnnotatedCode.c
)

add_custom_command(OUTPUT
	${ANNOTATED_CODE_SOURCES}
	DEPENDS r2ghidra
)

# Add libraries.
add_library(r2annotations
	${ANNOTATED_CODE_SOURCES}
)

add_dependencies(r2annotations r2ghidra)
target_include_directories(r2annotations PUBLIC ${source_dir}/src)
target_link_libraries(r2annotations Radare2::libr)
