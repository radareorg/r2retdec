cmake_minimum_required(VERSION 3.8)

include(FetchContent)

FetchContent_Declare(iaito
	GIT_REPOSITORY https://github.com/radareorg/iaito
	GIT_TAG master
)

FetchContent_GetProperties(iaito)
if(NOT Iaito_POPULATED)
	FetchContent_Populate(iaito)
	find_path(Iaito_SOURCE_ROOT
			NAMES core/Iaito.h
			PATHS "${iaito_SOURCE_DIR}"
			PATH_SUFFIXES src
			NO_DEFAULT_PATH
	)
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Iaito
		REQUIRED_VARS Iaito_SOURCE_ROOT
		FAIL_MESSAGE "Fetching Iaito sources failed"
)

if(Iaito_FOUND)
	set(IAITO_INCLUDE_DIRS "${Iaito_SOURCE_ROOT}" "${Iaito_SOURCE_ROOT}/common" "${Iaito_SOURCE_ROOT}/core")
	add_library(Iaito::Iaito INTERFACE IMPORTED GLOBAL)
	target_include_directories(Iaito::Iaito INTERFACE ${IAITO_INCLUDE_DIRS})
endif()
