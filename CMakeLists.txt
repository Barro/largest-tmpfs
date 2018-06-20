cmake_minimum_required(VERSION 3.0)
project(largest-ramfs LANGUAGES C)
include(GNUInstallDirs)

add_executable(largest-ramfs largest-ramfs.c main.c)
install(TARGETS largest-ramfs
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(largest-ramfs-fuzz fuzz.c)
