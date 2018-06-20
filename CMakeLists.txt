cmake_minimum_required(VERSION 3.0)
project(largest-tmpfs LANGUAGES C)
include(GNUInstallDirs)

add_library(largest-tmpfs-lib largest-tmpfs.c)
set_target_properties(largest-tmpfs-lib PROPERTIES OUTPUT_NAME largest-tmpfs)
set_target_properties(largest-tmpfs-lib PROPERTIES PUBLIC_HEADER largest-tmpfs.h)

add_executable(largest-tmpfs main.c)
target_link_libraries(largest-tmpfs largest-tmpfs-lib)

install(TARGETS largest-tmpfs largest-tmpfs-lib
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

file(READ version.txt PACKAGE_VERSION_raw)
string(STRIP "${PACKAGE_VERSION_raw}" PACKAGE_VERSION)
set(includedir "${CMAKE_INSTALL_INCLUDEDIR}")
set(libdir "${CMAKE_INSTALL_LIBDIR}")
configure_file("liblargest-tmpfs.pc.in" "liblargest-tmpfs.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/liblargest-tmpfs.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

add_executable(largest-tmpfs-fuzz fuzz.c)
