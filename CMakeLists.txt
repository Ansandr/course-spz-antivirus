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

# Copy signatures.db next to the executable after each build.
add_custom_command(TARGET AntivirusMVP POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/signatures.db"
        "$<TARGET_FILE_DIR:AntivirusMVP>/signatures.db"
    COMMENT "Copying signatures.db to output directory"
)

if(WIN32)
    # Deploy Qt runtime DLLs into build/<Config>/ so the app can run directly
    # after building both Debug and Release from VS Code / CMake Tools.
    get_target_property(QT_QMAKE_EXECUTABLE Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(QT_BIN_DIR "${QT_QMAKE_EXECUTABLE}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${QT_BIN_DIR}")

    if(WINDEPLOYQT_EXECUTABLE)
        add_custom_command(TARGET AntivirusMVP POST_BUILD
            COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                "$<$<CONFIG:Debug>:--debug>$<$<NOT:$<CONFIG:Debug>>:--release>"
                --no-translations
                --no-opengl-sw
                --dir "$<TARGET_FILE_DIR:AntivirusMVP>"
                "$<TARGET_FILE:AntivirusMVP>"
            COMMENT "Deploying Qt runtime with windeployqt"
            VERBATIM
        )
    else()
        message(WARNING "windeployqt was not found. AntivirusMVP may fail to run due to missing Qt DLLs.")
    endif()
endif()
