cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
project(netscan
    VERSION 1
    DESCRIPTION "Network mac address scanner"
    HOMEPAGE_URL "https://github.com/glguy/netscan"
    LANGUAGES C CXX
)

include(GNUInstallDirs)
find_package(PkgConfig REQUIRED)
add_subdirectory(netscan)
