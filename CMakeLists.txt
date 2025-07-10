cmake_minimum_required(VERSION 3.16)
project(XSalsa20 VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build test executables" ON)
option(BUILD_BENCHMARKS "Build benchmark executables" ON)
option(BUILD_SHARED "Build shared library" OFF)
option(BUILD_STATIC "Build static library" ON)
option(IMPL_SCALAR "Build scalar implementation" ON)
option(IMPL_AVX "Build AVX implementation" ON)
option(IMPL_AVX2 "Build AVX2 implementation" ON)
option(IMPL_AVX512 "Build AVX-512 implementation" ON)

# Architecture detection
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i386|i686")
    set(XSALSA_ARCH_X86 TRUE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(XSALSA_ARCH_ARM TRUE)
    # Disable vector implementations on ARM architectures
    set(IMPL_AVX OFF)
    set(IMPL_AVX2 OFF)
    set(IMPL_AVX512 OFF)
endif()

# Optimization levels
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Set default optimization flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        set(CMAKE_C_FLAGS_DEBUG "/Zi /Od")
    else()
        set(CMAKE_C_FLAGS_DEBUG "-g -O0")
    endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
    else()
        set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    if(MSVC)
        set(CMAKE_C_FLAGS_RELWITHDEBINFO "/O2 /Zi /DNDEBUG")
    else()
        set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
    endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    if(MSVC)
        set(CMAKE_C_FLAGS_MINSIZEREL "/O1 /DNDEBUG")
    else()
        set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
    endif()
endif()


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Build source list based on enabled implementations
set(XSALSA20_SOURCES xsalsa_impl_check.c xsalsa_runtime.c)
set(XSALSA20_HEADERS xsalsa.h)

# Function-specific compilation flags for vector implementations
if(IMPL_AVX)
    add_definitions(-DXSALSA_USE_IMPL_AVX)
    if(MSVC)
        set(AVX_FLAGS "/arch:AVX")
    else()
        set(AVX_FLAGS "-mavx")
    endif()
    list(APPEND XSALSA20_SOURCES xsalsa_avx.c)
    list(APPEND XSALSA20_HEADERS xsalsa_avx.h)
endif()

if(IMPL_AVX2)
    add_definitions(-DXSALSA_USE_IMPL_AVX2)
    if(MSVC)
        set(AVX2_FLAGS "/arch:AVX2")
    else()
        set(AVX2_FLAGS "-mavx2")
    endif()
    list(APPEND XSALSA20_SOURCES xsalsa_avx2.c)
    list(APPEND XSALSA20_HEADERS xsalsa_avx2.h)
endif()

if(IMPL_AVX512)
    add_definitions(-DXSALSA_USE_IMPL_AVX512)
    if(MSVC)
        set(AVX512_FLAGS "/arch:AVX512")
    else()
        set(AVX512_FLAGS "-mavx512f")
    endif()
    list(APPEND XSALSA20_SOURCES xsalsa_avx512.c)
    list(APPEND XSALSA20_HEADERS xsalsa_avx512.h)
endif()

if(IMPL_SCALAR)
    add_definitions(-DXSALSA_USE_IMPL_SCALAR)
    list(APPEND XSALSA20_SOURCES xsalsa_scalar.c)
    list(APPEND XSALSA20_HEADERS xsalsa_scalar.h)
endif()

# Add architecture-specific definitions
if(XSALSA_ARCH_X86)
    add_definitions(-DXSALSA_ARCH_X86)
elseif(XSALSA_ARCH_ARM)
    add_definitions(-DXSALSA_ARCH_ARM)
endif()


# Ensure at least one implementation is enabled
if(NOT IMPL_SCALAR AND NOT IMPL_AVX AND NOT IMPL_AVX2 AND NOT IMPL_AVX512)
    message(FATAL_ERROR "At least one implementation (IMPL_SCALAR, IMPL_AVX, IMPL_AVX2, or IMPL_AVX512) must be enabled")
endif()

if(BUILD_STATIC)
    add_library(xsalsa20_static STATIC ${XSALSA20_SOURCES})
    set_target_properties(xsalsa20_static PROPERTIES
        OUTPUT_NAME xsalsa20
        PUBLIC_HEADER "${XSALSA20_HEADERS}"
    )
    target_include_directories(xsalsa20_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
    )
endif()

if(BUILD_SHARED)
    add_library(xsalsa20_shared SHARED ${XSALSA20_SOURCES})
    set_target_properties(xsalsa20_shared PROPERTIES
        OUTPUT_NAME xsalsa20
        PUBLIC_HEADER "${XSALSA20_HEADERS}"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_include_directories(xsalsa20_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
    )
endif()

if(IMPL_AVX)
    set_source_files_properties(xsalsa_avx.c PROPERTIES COMPILE_FLAGS "${AVX_FLAGS}")
endif()
if(IMPL_AVX2)
    set_source_files_properties(xsalsa_avx2.c PROPERTIES COMPILE_FLAGS "${AVX2_FLAGS}")
endif()
if(IMPL_AVX512)
    set_source_files_properties(xsalsa_avx512.c PROPERTIES COMPILE_FLAGS "${AVX512_FLAGS}")
endif()

if(BUILD_TESTS)
    add_executable(test_xsalsa test_xsalsa.c)
    if(BUILD_STATIC)
        target_link_libraries(test_xsalsa xsalsa20_static)
    elseif(BUILD_SHARED)
        target_link_libraries(test_xsalsa xsalsa20_shared)
    endif()
endif()

if(BUILD_BENCHMARKS)
    add_executable(bench_xsalsa bench_xsalsa.c)
    if(BUILD_STATIC)
        target_link_libraries(bench_xsalsa xsalsa20_static)
    elseif(BUILD_SHARED)
        target_link_libraries(bench_xsalsa xsalsa20_shared)
    endif()
endif()

include(GNUInstallDirs)

install(FILES ${XSALSA20_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/xsalsa20
)

if(BUILD_STATIC)
    install(TARGETS xsalsa20_static
        EXPORT XSalsa20Targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/xsalsa20
    )
endif()

if(BUILD_SHARED)
    install(TARGETS xsalsa20_shared
        EXPORT XSalsa20Targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/xsalsa20
    )
endif()

if(BUILD_TESTS)
    install(TARGETS test_xsalsa
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if(BUILD_BENCHMARKS)
    install(TARGETS bench_xsalsa
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

install(EXPORT XSalsa20Targets
    FILE XSalsa20Targets.cmake
    NAMESPACE XSalsa20::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XSalsa20
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/XSalsa20ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/XSalsa20Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/XSalsa20Config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XSalsa20
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/XSalsa20Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/XSalsa20ConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XSalsa20
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/xsalsa20.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/xsalsa20.pc"
    @ONLY
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/xsalsa20.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

enable_testing()
if(BUILD_TESTS)
    add_test(NAME XSalsa20Test COMMAND test_xsalsa)
    
    # Set test properties to handle single implementation
    if(IMPL_SCALAR)
        set_tests_properties(XSalsa20Test PROPERTIES
            ENVIRONMENT "XSALSA20_TEST_SCALAR_ONLY=1"
        ) 
    elseif(IMPL_AVX)
        set_tests_properties(XSalsa20Test PROPERTIES
            ENVIRONMENT "XSALSA20_TEST_AVX_ONLY=1"
        )
    endif()
endif() 