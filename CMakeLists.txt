cmake_minimum_required(VERSION 3.12)

project(retdec-r2plugin C CXX)

# Minimal required version
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set the default build type to 'Release'
if(NOT CMAKE_BUILD_TYPE)
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

# Build parameters.
if(MSVC) # Windows
	# Disable warnings (there are too many of them, including warnings from
	# third-party libraries, which cannot be selectively disabled when using MSVC).
	string(REGEX REPLACE "/W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W0")

	# Disable the min() and max() macros to prevent errors when using e.g.
	# std::numeric_limits<...>::max()
	# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DNOMINMAX")
elseif(UNIX) # Linux or macOS
	# Common options.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

	# Set C flags
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
else()
	message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

# On Linux and macOS, set RPATH relative to the origin of the installed
# executables (i.e. relative to the bin directory). This allows us to move the
# installation directory into a different location after installation, which is
# useful e.g. when the installation is performed on one machine but we want to
# run the executables on a different machine.
#
# On Windows, there is no need to set anything as DLLs are installed into the
# bin directory, where they are automatically picked up by executables.
#
# For more details, see
#  - https://github.com/avast/retdec/issues/77
#  - https://cmake.org/Wiki/CMake_RPATH_handling
if(APPLE)
        set(CMAKE_INSTALL_RPATH "@executable_path/../lib")
elseif(UNIX)
        set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
endif()

option(R2PLUGIN_DOC "Build r2plugin documentation" OFF)
if (R2PLUGIN_DOC)
	add_subdirectory(doc)
endif()

get_filename_component(RADARE_INSTALL_PATH "${RADARE_INSTALL_PATH}" REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")

set(RADARE2_INSTALL_PLUGDIR "share/radare2/plugins" CACHE PATH "Directory to install radare2 plugin into")
set(CUTTER_INSTALL_PLUGDIR "share/RadareOrg/Cutter/plugins/native" CACHE PATH "Directory to install Cutter plugin into")

if (RETDEC_INSTALL_PREFIX)
	set(RADARE2_INSTALL_PLUGDIR "${CMAKE_INSTALL_PREFIX}/${RADARE2_INSTALL_PLUGDIR}")
	set(CUTTER_INSTALL_PLUGDIR "${CMAKE_INSTALL_PREFIX}/${CUTTER_INSTALL_PLUGDIR}")
	if (IS_ABSOLUTE "${RETDEC_INSTALL_PREFIX}")
		set(CMAKE_INSTALL_PREFIX "${RETDEC_INSTALL_PREFIX}")
	else()
		get_filename_component(CMAKE_INSTALL_PREFIX "${RETDEC_INSTALL_PREFIX}" REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")
	endif()
endif()

option(BUILD_CUTTER_PLUGIN "Build r2retdec plugin for Cutter" OFF)
option(BUILD_BUNDLED_RETDEC "Build retdec with the r2retdec plugin" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Radare2 REQUIRED)

add_subdirectory(deps)
add_subdirectory(src)
add_subdirectory(support)
