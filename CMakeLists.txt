cmake_minimum_required(VERSION 3.0)
project(largest-tmpfs LANGUAGES C)
include(GNUInstallDirs)

# $$(cat<${CMAKE_CURRENT_SOURCE_DIR}/version.txt)
#$$(uname)
add_custom_command(OUTPUT config.h
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/create-config.h.sh" "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    DEPENDS version.txt create-config.h.sh)
add_custom_target(generate-config.h DEPENDS config.h)

add_library(largest-tmpfs-lib largest-tmpfs.c)
set_target_properties(largest-tmpfs-lib PROPERTIES OUTPUT_NAME largest-tmpfs)
set_target_properties(largest-tmpfs-lib PROPERTIES PUBLIC_HEADER largest-tmpfs.h)

add_executable(largest-tmpfs main.c)
target_compile_definitions(largest-tmpfs PRIVATE -DHAVE_CONFIG_H)
target_link_libraries(largest-tmpfs largest-tmpfs-lib)
target_include_directories(largest-tmpfs PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(largest-tmpfs generate-config.h)

install(TARGETS largest-tmpfs largest-tmpfs-lib
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

set(includedir "${CMAKE_INSTALL_INCLUDEDIR}")
set(libdir "${CMAKE_INSTALL_LIBDIR}")
configure_file("liblargest-tmpfs.pc.in" "liblargest-tmpfs.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/liblargest-tmpfs.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

add_executable(largest-tmpfs-fuzz fuzz.c)
