cmake_minimum_required(VERSION 4.1)

#Declare languages explicitly
project(WGObfuscator 
    VERSION 1.0.0
    DESCRIPTION "WireGuard Packet Obfuscator for iOS/macOS"
    LANGUAGES Swift
)

# Set Swift language version
if(NOT XCODE_VERSION VERSION_LESS 10.2)
    set(CMAKE_Swift_LANGUAGE_VERSION 6.0)
endif()

# Use generator expression for module directory (best practice)
set(CMAKE_Swift_MODULE_DIRECTORY
    "${CMAKE_BINARY_DIR}/swift/$<IF:$<CONFIG:Debug>,debug,release>")

# Compilation mode configuration with generator expressions
set(CMAKE_Swift_COMPILATION_MODE
    "$<IF:$<CONFIG:Release>,wholemodule,incremental>")

# Enable strict concurrency for Swift 6
set(CMAKE_Swift_FLAGS 
    "-strict-concurrency=complete -enable-experimental-feature StrictConcurrency")

# Library target
add_library(WGObfuscator
    Sources/WGObfuscator/Core/ObfuscationEngine.swift
    Sources/WGObfuscator/Core/PacketCodec.swift
    Sources/WGObfuscator/Core/WireGuardTypes.swift
    Sources/WGObfuscator/Core/CryptoUtilities.swift
    Sources/WGObfuscator/Masking/MaskingProtocol.swift
    Sources/WGObfuscator/Masking/STUNMasker.swift
    Sources/WGObfuscator/Masking/STUNPacket.swift
    Sources/WGObfuscator/Masking/MaskingFactory.swift
    Sources/WGObfuscator/Proxy/UDPProxy.swift
    Sources/WGObfuscator/Proxy/ClientSession.swift
    Sources/WGObfuscator/Proxy/NATTable.swift
)

# Target properties (no global variables!)
set_target_properties(WGObfuscator PROPERTIES
    Swift_COMPILATION_MODE "$<IF:$<CONFIG:Release>,wholemodule,incremental>"
    Swift_MODULE_NAME WGObfuscator
    Swift_MODULE_DIRECTORY "${CMAKE_Swift_MODULE_DIRECTORY}"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Link frameworks using target-based approach
target_link_libraries(WGObfuscator PUBLIC
    "-framework Network"
    "-framework Foundation"
)

# Include directory specification
target_include_directories(WGObfuscator
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/Sources>
        $<INSTALL_INTERFACE:include>
)

# Xcode-specific properties (generator expression pattern)
if(CMAKE_GENERATOR MATCHES "Xcode")
    set_target_properties(WGObfuscator PROPERTIES
        XCODE_ATTRIBUTE_SWIFT_VERSION 6.0
        XCODE_ATTRIBUTE_ENABLE_TESTABILITY YES
        XCODE_ATTRIBUTE_SWIFT_OPTIMIZATION_LEVEL 
            "$<IF:$<CONFIG:Debug>,-Onone,-O>"
        XCODE_ATTRIBUTE_SWIFT_ACTIVE_COMPILATION_CONDITIONS
            "$<$<CONFIG:Debug>:DEBUG>"
    )
    
    # Enable folder organization for IDE
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
    set_property(TARGET WGObfuscator PROPERTY FOLDER "Libraries")
endif()

# Enable testing
enable_testing()

# Test executable with proper language-specific options
add_executable(WGObfuscatorTests
    Tests/WGObfuscatorTests/Core/ObfuscationEngineTests.swift
    Tests/WGObfuscatorTests/Core/PacketCodecTests.swift
    Tests/WGObfuscatorTests/Core/CryptoUtilitiesTests.swift
    Tests/WGObfuscatorTests/Masking/STUNMaskerTests.swift
    Tests/WGObfuscatorTests/Masking/STUNPacketTests.swift
    Tests/WGObfuscatorTests/Integration/EndToEndTests.swift
)

# Link test target to library
target_link_libraries(WGObfuscatorTests PRIVATE 
    WGObfuscator
    "-framework XCTest"
)

# Compile options specific to test target
target_compile_options(WGObfuscatorTests PRIVATE
    "$<$<COMPILE_LANGUAGE:Swift>:-enable-testing>"
)

# Register tests using generator expression
add_test(NAME WGObfuscatorTests 
         COMMAND $<TARGET_FILE:WGObfuscatorTests>
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

# Set test properties for better debugging
set_target_properties(WGObfuscatorTests PROPERTIES
    FOLDER "Tests"
    Swift_COMPILATION_MODE "incremental"
)

if(CMAKE_GENERATOR MATCHES "Xcode")
    set_target_properties(WGObfuscatorTests PROPERTIES
        XCODE_ATTRIBUTE_ENABLE_TESTABILITY YES
    )
endif()

# Installation and Export
install(TARGETS WGObfuscator
    EXPORT WGObfuscatorTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

# Install Swift modules
install(DIRECTORY ${CMAKE_Swift_MODULE_DIRECTORY}/
    DESTINATION include/WGObfuscator
    FILES_MATCHING PATTERN "*.swiftmodule"
)

# Export targets
install(EXPORT WGObfuscatorTargets
    FILE WGObfuscatorTargets.cmake
    NAMESPACE WGObfuscator::
    DESTINATION lib/cmake/WGObfuscator
)

# Generate config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/WGObfuscatorConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/WGObfuscatorConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/WGObfuscatorConfig.cmake"
    INSTALL_DESTINATION lib/cmake/WGObfuscator
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/WGObfuscatorConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/WGObfuscatorConfigVersion.cmake"
    DESTINATION lib/cmake/WGObfuscator
)
