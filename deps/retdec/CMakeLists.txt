cmake_minimum_required(VERSION 3.8)

include(FetchContent)

if (RETDEC_INSTALL_PREFIX)
	set(RETDEC_INSTALL_DIR "${RETDEC_INSTALL_PREFIX}")
else ()
	set(RETDEC_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/retdec-install")
endif ()

FetchContent_Declare(retdec
	URL https://github.com/avast/retdec/archive/e0d5a60e604c3443ae9f095da88be5e1bcbf659b.zip
	URL_HASH SHA256=9caa2bd5c06547b3dc5468b839a8d3a0cd3394f7f9da36db1a5ca06172af4962
	)

FetchContent_GetProperties(retdec)
if(NOT retdec_POPULATED)
	FetchContent_Populate(retdec)
	if (${BUILD_BUNDLED_RETDEC})
		option(RETDEC_ENABLE_CONFIG "" OFF)
	else()
		option(RETDEC_ENABLE_CONFIG "" ON)
	endif()

	add_subdirectory(
		${retdec_SOURCE_DIR}
		${retdec_BINARY_DIR}
	)
endif()
