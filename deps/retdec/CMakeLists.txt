cmake_minimum_required(VERSION 3.8)

project(retdec-build-system-tests
	LANGUAGES C CXX
)

macro(retdec_install)
	set(RETDEC_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/retdec-download")
	if (RETDEC_INSTALL_PREFIX)
		set(RETDEC_INSTALL_DIR "${RETDEC_INSTALL_PREFIX}")
	else ()
		set(RETDEC_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/retdec-install")
	endif ()

	# Configure RetDec installation script.
	set(RETDEC_ENABLE_OPTIONS "${ARGV0}")
	configure_file(
		"${PROJECT_SOURCE_DIR}/deps/retdec/retdec-install.cmake.in"
		"${RETDEC_DOWNLOAD_DIR}/CMakeLists.txt"
	)

	add_library(rapidjson INTERFACE)
	target_include_directories(rapidjson
		SYSTEM INTERFACE
		${RETDEC_DOWNLOAD_DIR}/deps/rapidjson/include
	)
	target_compile_definitions(rapidjson
		INTERFACE
		RAPIDJSON_HAS_STDSTRING=1
		RAPIDJSON_HAS_CXX11_RVALUE_REFS=1
	)

	# Configure RetDec build.
	execute_process(
		COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" -A "${CMAKE_GENERATOR_PLATFORM}" .
		WORKING_DIRECTORY "${RETDEC_DOWNLOAD_DIR}"
	)
	
	# Build and install RetDec.
	if(MSVC)
		execute_process(
			COMMAND "${CMAKE_COMMAND}" --build . --config Release -- -m
			WORKING_DIRECTORY "${RETDEC_DOWNLOAD_DIR}"
		)
	else()
		include(ProcessorCount)
		ProcessorCount(N)
		execute_process(
			COMMAND "${CMAKE_COMMAND}" --build . -- -j${N}
			WORKING_DIRECTORY "${RETDEC_DOWNLOAD_DIR}"
		)
	endif()

	# Add RetDec installation directory to CMake prefix
	# -> find_package() will be able to find RetDec and its components.
	# NOTE:
	#   This may cause confusion between multiple installed RetDecs.
	#   E.g. utils & yaracpp installed, retdec-config.cmake from utils tries
	#   to find yaracpp config because it thinks it is its component.
	#list(APPEND CMAKE_PREFIX_PATH "${RETDEC_INSTALL_DIR}")
	# This does not have the same problem.
	set(retdec_DIR "${RETDEC_INSTALL_DIR}/share/retdec/cmake")
endmacro()

macro(retdec_install_config)
	retdec_install("-D RETDEC_ENABLE_CONFIG=ON")
endmacro()
