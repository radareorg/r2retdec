cmake_minimum_required(VERSION 3.8)

include(FetchContent)

if (RETDEC_INSTALL_PREFIX)
	set(RETDEC_INSTALL_DIR "${RETDEC_INSTALL_PREFIX}")
else ()
	set(RETDEC_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/retdec-install")
endif ()

FetchContent_Declare(retdec
	URL https://github.com/avast/retdec/archive/d780a9e8cc80662dc8a877016348f787e79c1338.zip
	URL_HASH SHA256=8e603581ceaed3e806009277edbb26c5ebbd9c7f476f8dbe5617ed3124548915
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
		${RETDEC_INSTALL_DIR}
	)
endif()
