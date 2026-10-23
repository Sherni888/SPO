cmake_minimum_required(VERSION 3.25)
project(SPO CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/GS- /O2 /W3 /WX- /MP /utf-8)
    add_compile_options(/wd4996 /wd4200)
    add_link_options(/INCREMENTAL:NO /LTCG)
endif()

set(USERMODE_SOURCES
    ${CMAKE_SOURCE_DIR}/../src/usermode/main.cpp
    ${CMAKE_SOURCE_DIR}/../src/usermode/backup.cpp
    ${CMAKE_SOURCE_DIR}/../src/usermode/spoof_registry.cpp
    ${CMAKE_SOURCE_DIR}/../src/usermode/spoof_nic.cpp
    ${CMAKE_SOURCE_DIR}/../src/usermode/spoof_edid.cpp
    ${CMAKE_SOURCE_DIR}/../src/usermode/spoof_gpu.cpp
)

add_executable(spo ${USERMODE_SOURCES})
target_include_directories(spo PRIVATE ${CMAKE_SOURCE_DIR}/../src/usermode)
target_link_libraries(spo PRIVATE iphlpapi.lib setupapi.lib shlwapi.lib advapi32.lib)
set_target_properties(spo PROPERTIES
    OUTPUT_NAME "spo"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_executable(loader ${CMAKE_SOURCE_DIR}/../loader/loader.cpp)
target_include_directories(loader PRIVATE ${CMAKE_SOURCE_DIR}/../src/usermode)
target_link_libraries(loader PRIVATE advapi32.lib ntdll.lib)
set_target_properties(loader PROPERTIES
    OUTPUT_NAME "loader"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

message(STATUS "Kernel driver: build with WDK via build/kernel/spo_drv.vcxproj")
