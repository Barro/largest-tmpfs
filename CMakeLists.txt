cmake_minimum_required(VERSION 3.0)
project(largest-tmpfs LANGUAGES C)
include(GNUInstallDirs)

add_executable(largest-tmpfs largest-tmpfs.c main.c)
install(TARGETS largest-tmpfs
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(largest-tmpfs-fuzz fuzz.c)
