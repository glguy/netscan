pkg_check_modules(FMT  REQUIRED IMPORTED_TARGET fmt)
find_package(Boost)

if(APPLE)
        find_library(PCAP libpcap.tbd REQUIRED)
else()
        pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
        set(PCAP PkgConfig::PCAP)
endif()

add_executable(netscan
    BpfProgram.cpp Pcap.cpp PosixSpawnFileActions.cpp LocalSignalHandler.cpp
    PosixSpawn.cpp main.cpp MyLibC.cpp PosixSpawnAttr.cpp)

target_link_libraries(netscan PRIVATE PkgConfig::FMT Boost::headers)

if(APPLE)
    find_library(PCAP libpcap.tbd REQUIRED)
    target_link_libraries(netscan PRIVATE PCAP)
else()
    pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
    target_link_libraries(netscan PRIVATE PkgConfig::PCAP)
endif()
