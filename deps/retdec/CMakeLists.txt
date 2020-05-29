cmake_minimum_required(VERSION 3.8)

include(FetchContent)

if (RETDEC_INSTALL_PREFIX)
	set(RETDEC_INSTALL_DIR "${RETDEC_INSTALL_PREFIX}")
else ()
	set(RETDEC_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/retdec-install")
endif ()

FetchContent_Declare(retdec
	URL https://github.com/avast/retdec/archive/094ff8cebe1ccc8c0f7093599f9d5a4c4e7bbce6.zip
	URL_HASH SHA256=c1bb88a5e95a6f617b2ccf1210aa4eaa675e1bb3964332083fc74c5d38367ca0
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
