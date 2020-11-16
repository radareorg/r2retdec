cmake_minimum_required(VERSION 3.8)

include(FetchContent)

FetchContent_Declare(retdec
	GIT_REPOSITORY https://github.com/avast/retdec
	GIT_TAG 73184b0c17b8790ab691217d2ab4cb6d569495fb # TODO use branch_name or tag_name
	GIT_PROGRESS TRUE
	#GIT_SHALLOW TRUE # requires GIT_TAG to be branch_name or tag_name
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
