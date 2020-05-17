cmake_minimum_required(VERSION 3.8)

include(FetchContent)

if (RETDEC_INSTALL_PREFIX)
	set(RETDEC_INSTALL_DIR "${RETDEC_INSTALL_PREFIX}")
else ()
	set(RETDEC_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/retdec-install")
endif ()

FetchContent_Declare(retdec
	URL https://github.com/avast/retdec/archive/abb2b985cccc70ae8921266793f3fa9f64bf1ac8.zip
	URL_HASH SHA256=863b5251844e0a869119f776a828bcd6e824cdc8f28420c6127aa0b6f31bfd2b
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
