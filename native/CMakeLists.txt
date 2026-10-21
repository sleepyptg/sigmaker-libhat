cmake_minimum_required(VERSION 3.23)

project(libhat_sigmaker_native VERSION 0.2.1 LANGUAGES CXX)

# The sibling checkout is used by default so the bridge and the Python plugin
# can be developed side by side. A standalone checkout can point CMake at a
# libhat source tree, or let FetchContent download the pinned release.
set(LIBHAT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../libhat" CACHE PATH
    "Path to a libhat source checkout")

# Keep libhat's tests, examples, install rules, and warning-as-error policy out
# of this build. These must be set before libhat's CMakeLists is evaluated by
# either FetchContent_MakeAvailable() or add_subdirectory().
set(LIBHAT_TESTING OFF CACHE BOOL "" FORCE)
set(LIBHAT_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIBHAT_INSTALL_TARGET OFF CACHE BOOL "" FORCE)
set(LIBHAT_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)

if(EXISTS "${LIBHAT_SOURCE_DIR}/CMakeLists.txt")
    message(STATUS "Using libhat source: ${LIBHAT_SOURCE_DIR}")
else()
    message(STATUS "libhat checkout not found; fetching BasedInc/libhat v0.11.1")
    include(FetchContent)
    FetchContent_Declare(
        libhat
        GIT_REPOSITORY https://github.com/BasedInc/libhat.git
        GIT_TAG        v0.11.1
        GIT_SHALLOW    TRUE
    )
    # MakeAvailable already adds the downloaded source directory, so the
    # add_subdirectory() below is only for an explicit LIBHAT_SOURCE_DIR.
    FetchContent_MakeAvailable(libhat)
    set(LIBHAT_SOURCE_DIR "${libhat_SOURCE_DIR}" CACHE PATH "" FORCE)
endif()

if(NOT TARGET libhat)
    add_subdirectory("${LIBHAT_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/libhat" EXCLUDE_FROM_ALL)
endif()

add_library(libhat_scan SHARED scan_bridge.cpp)

target_compile_features(libhat_scan PRIVATE cxx_std_20)
target_link_libraries(libhat_scan PRIVATE libhat::libhat)
target_compile_definitions(libhat_scan PRIVATE
    LIBHAT_SCAN_VERSION_STRING="${PROJECT_VERSION}"
)

set_target_properties(libhat_scan PROPERTIES
    PREFIX ""
    OUTPUT_NAME "libhat_scan"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN TRUE
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

if(MSVC)
    target_compile_options(libhat_scan PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(libhat_scan PRIVATE -Wall -Wextra -Wpedantic)
endif()
