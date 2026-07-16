cmake_minimum_required(VERSION 3.10)
project(apps LANGUAGES C)

if(NOT DEFINED KP_DIR)
    set(KP_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -g0" CACHE STRING "Release flags" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-DNDEBUG -g0" CACHE STRING "RelWithDebInfo flags" FORCE)

set(KERNEL_INCLUDE_DIRS
    . include patch/include linux/include
    linux/arch/arm64/include linux/tools/arch/arm64/include
)

set(GLOBAL_INCLUDE_DIRS "")
foreach(dir ${KERNEL_INCLUDE_DIRS})
    list(APPEND GLOBAL_INCLUDE_DIRS "${KP_DIR}/kernel/${dir}")
endforeach()

function(add_kpm_module MODULE_NAME)
    set(multiValueArgs SOURCES)
    cmake_parse_arguments(KPM "" "" "${multiValueArgs}" ${ARGN})
    if(KPM_SOURCES)
        set(SOURCE_FILES ${KPM_SOURCES})
    elseif(KPM_UNPARSED_ARGUMENTS)
        set(SOURCE_FILES ${KPM_UNPARSED_ARGUMENTS})
    else()
        message(FATAL_ERROR "add_kpm_module: No source files for ${MODULE_NAME}")
    endif()

    add_library(${MODULE_NAME}_obj OBJECT ${SOURCE_FILES})
    target_include_directories(${MODULE_NAME}_obj PRIVATE ${GLOBAL_INCLUDE_DIRS})
    target_compile_options(${MODULE_NAME}_obj PRIVATE
        -Os -fno-stack-protector -fno-builtin -nostdinc
        -fno-PIC -mno-outline-atomics -mcmodel=large
        -fno-asynchronous-unwind-tables -fno-unwind-tables
    )

    add_custom_target(${MODULE_NAME}.kpm ALL
        COMMAND ${CMAKE_C_COMPILER} -r -o ${MODULE_NAME}.kpm "$<TARGET_OBJECTS:${MODULE_NAME}_obj>"
        DEPENDS ${MODULE_NAME}_obj
        COMMENT "Generating ${MODULE_NAME}.kpm"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND_EXPAND_LISTS
    )
endfunction()

file(GLOB CHILD_MODULES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/kpms ${CMAKE_CURRENT_SOURCE_DIR}/kpms/*)
foreach(child ${CHILD_MODULES})
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/kpms/${child}")
        add_subdirectory(kpms/${child})
    endif()
endforeach()
