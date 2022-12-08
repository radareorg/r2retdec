cmake_minimum_required(VERSION 3.13)

include(FetchContent)

FetchContent_Declare(retdec
	GIT_REPOSITORY https://github.com/avast/retdec
	GIT_TAG 53e55b4b26e9b843787f0e06d867441e32b1604e
)

FetchContent_GetProperties(retdec)
if(NOT retdec_POPULATED)
	FetchContent_Populate(retdec)

	add_subdirectory(
		${retdec_SOURCE_DIR}
		${retdec_BINARY_DIR}
	)

	install(
		DIRECTORY
			"${retdec_SOURCE_DIR}/support/ordinals"
			"${retdec_SOURCE_DIR}/support/yara_patterns"
			"${retdec_SOURCE_DIR}/support/types"
		DESTINATION
			"${RADARE2_INSTALL_PLUGDIR}/support/retdec/"
	)
endif()
