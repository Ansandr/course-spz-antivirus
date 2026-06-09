cmake_minimum_required(VERSION 3.20)
project(AntivirusMVP VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Test)

enable_testing()

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

function(add_antivirus_qt_test target_name source_file)
    add_executable(${target_name}
        ${source_file}
    )
    target_link_libraries(${target_name} PRIVATE
        antivirus_core
        Qt6::Core
        Qt6::Test
    )

    if(WIN32)
        # Ensure CTest can run each test binary without missing Qt runtime DLLs.
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy -t $<TARGET_FILE_DIR:${target_name}> $<TARGET_RUNTIME_DLLS:${target_name}>
            COMMAND_EXPAND_LISTS
        )
    endif()

    add_test(NAME ${target_name} COMMAND ${target_name})
endfunction()

add_antivirus_qt_test(test_signaturedb tests/test_signaturedb.cpp)
add_antivirus_qt_test(test_scanner tests/test_scanner.cpp)
add_antivirus_qt_test(test_quarantine tests/test_quarantine.cpp)
