if (NOT BUILD_BUNDLED_RETDEC)
	set(RETDEC_VERSION 4.0)
	find_package(retdec ${RETDEC_VERSION} REQUIRED COMPONENTS retdec config)
endif()

# RetDec r2plugin sources.
set(SOURCES
	r2retdec.cpp
	r2data.cpp
	r2utils.cpp
	r2cgen.cpp
	console/console.cpp
	console/data_analysis.cpp
	console/decompiler.cpp
	registration.cpp
)

add_library(core_retdec SHARED ${SOURCES})

target_link_libraries(core_retdec
	retdec::retdec
	retdec::config
	Radare2::libr
)

if (MSVC)
	target_link_libraries(core_retdec
		retdec::bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::bin2llvmir>
		retdec::llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::llvmir2hll>
	)

	set_property(TARGET core_retdec
		APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE"
	)
	# Increase the stack size of the created binaries on MS Windows because the
	# default value is too small. The default Linux value is 8388608 (8 MB).
	set_property(TARGET core_retdec
		APPEND_STRING PROPERTY LINK_FLAGS " /STACK:16777216"
	)
	# Allow the 32b version of bin2llvmir on Windows handle addresses larger
	# than 2 GB (up to 4 GB).
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		set_property(TARGET retdec
			APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE"
		)
	endif()
elseif (APPLE)
	target_link_libraries(core_retdec
		-Wl,-force_load retdec::bin2llvmir
		-Wl,-force_load retdec::llvmir2hll
	)
else ()
	target_link_libraries(core_retdec
		-Wl,--whole-archive retdec::bin2llvmir -Wl,--no-whole-archive
		-Wl,--whole-archive retdec::llvmir2hll -Wl,--no-whole-archive
	)
endif()

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

install(TARGETS core_retdec DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
