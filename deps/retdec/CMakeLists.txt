cmake_minimum_required(VERSION 3.8)

include(FetchContent)

if (RETDEC_INSTALL_PREFIX)
	set(RETDEC_INSTALL_DIR "${RETDEC_INSTALL_PREFIX}")
else ()
	set(RETDEC_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/retdec-install")
endif ()

FetchContent_Declare(retdec
	URL https://github.com/avast/retdec/archive/c169e9dd55ccca71d61eda05c50c9a2e9426e1e0.zip
	URL_HASH SHA256=e2ebbd243c1d370539772f37b71ff158d89fb082d0a3f80303c4810c952e3571
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
