add_subdirectory(retdec)
add_subdirectory(annotations)

if (BUILD_CUTTER_PLUGIN)
	add_subdirectory(cutter)
endif()
