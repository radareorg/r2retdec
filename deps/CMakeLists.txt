if (BUILD_BUNDLED_RETDEC)
	add_subdirectory(retdec)
endif()

if (BUILD_CUTTER_PLUGIN)
	add_subdirectory(cutter)
endif()
