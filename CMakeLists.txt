cmake_minimum_required(VERSION 3.20)
project(AntivirusMVP VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

# ─── Core static library (antivirus_core) ────────────────────────────────────
add_library(antivirus_core STATIC
    src/logger.cpp
    src/logger.h
    src/processlist.cpp
    src/processlist.h
    src/quarantine.cpp
    src/quarantine.h
    src/reportwriter.cpp
    src/reportwriter.h
    src/scanner.cpp
    src/scanner.h
    src/signaturedb.cpp
    src/signaturedb.h
)
target_include_directories(antivirus_core PUBLIC src)
target_link_libraries(antivirus_core PUBLIC Qt6::Core)

if(WIN32)
    target_link_libraries(antivirus_core PUBLIC psapi)
endif()

# ─── GUI executable ───────────────────────────────────────────────────────────
add_executable(AntivirusMVP WIN32
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
)

target_link_libraries(AntivirusMVP PRIVATE
    antivirus_core
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)
