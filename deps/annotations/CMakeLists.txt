set(ANNOTATION_SOURCES
	src/AnnotatedCode.c
)

# Add libraries.
add_library(annotations
	${ANNOTATION_SOURCES}
)

target_include_directories(annotations PUBLIC include)


target_link_libraries(annotations Radare2::libr)
