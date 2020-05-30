cmake_minimum_required(VERSION 3.8)

include(FetchContent)

FetchContent_Declare(cutter
	GIT_REPOSITORY https://github.com/radareorg/cutter
	GIT_TAG v1.10.3
)

FetchContent_GetProperties(cutter)
if(NOT Cutter_POPULATED)
	FetchContent_Populate(cutter)
	find_path(Cutter_SOURCE_ROOT
			NAMES core/Cutter.h
			PATHS "${cutter_SOURCE_DIR}"
			PATH_SUFFIXES src
			NO_DEFAULT_PATH
	)
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Cutter
		REQUIRED_VARS Cutter_SOURCE_ROOT
		FAIL_MESSAGE "Fetching Cutter sources failed"
)

if(Cutter_FOUND)
	set(CUTTER_INCLUDE_DIRS "${Cutter_SOURCE_ROOT}" "${Cutter_SOURCE_ROOT}/common" "${Cutter_SOURCE_ROOT}/core")
	add_library(Cutter::Cutter INTERFACE IMPORTED GLOBAL)
	target_include_directories(Cutter::Cutter INTERFACE ${CUTTER_INCLUDE_DIRS})
endif()
