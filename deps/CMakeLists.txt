if (BUILD_BUNDLED_RETDEC)
	add_subdirectory(retdec)
endif()

if (BUILD_IAITO_PLUGIN)
	add_subdirectory(iaito)
endif()
