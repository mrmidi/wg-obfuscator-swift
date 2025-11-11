#!/bin/bash
set -e

echo "🚀 WireGuard Obfuscator - Swift Build Script"
echo "=============================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command
COMMAND=${1:-build}

case $COMMAND in
    build)
        echo -e "${BLUE}Building with Swift Package Manager...${NC}"
        swift build
        echo -e "${GREEN}✅ Build complete${NC}"
        ;;
        
    test)
        echo -e "${BLUE}Running tests...${NC}"
        swift test
        echo -e "${GREEN}✅ Tests complete${NC}"
        ;;
        
    clean)
        echo -e "${BLUE}Cleaning build artifacts...${NC}"
        rm -rf .build build-*
        echo -e "${GREEN}✅ Clean complete${NC}"
        ;;
        
    xcode)
        echo -e "${BLUE}Generating Xcode project...${NC}"
        cmake -G Xcode -S . -B build-xcode -DCMAKE_BUILD_TYPE=Debug
        open build-xcode/WGObfuscator.xcodeproj
        echo -e "${GREEN}✅ Xcode project opened${NC}"
        ;;
        
    ninja)
        echo -e "${BLUE}Building with Ninja...${NC}"
        cmake -G Ninja -S . -B build-ninja -DCMAKE_BUILD_TYPE=Release
        cmake --build build-ninja --parallel
        echo -e "${GREEN}✅ Ninja build complete${NC}"
        ;;
        
    release)
        echo -e "${BLUE}Building release version...${NC}"
        swift build -c release
        echo -e "${GREEN}✅ Release build complete${NC}"
        ;;
        
    format)
        echo -e "${BLUE}Formatting Swift code...${NC}"
        find Sources Tests -name "*.swift" -exec swift-format -i {} \;
        echo -e "${GREEN}✅ Format complete${NC}"
        ;;
        
    coverage)
        echo -e "${BLUE}Running tests with coverage...${NC}"
        swift test --enable-code-coverage
        xcrun llvm-cov report .build/debug/WGObfuscatorPackageTests.xctest/Contents/MacOS/WGObfuscatorPackageTests \
            -instr-profile .build/debug/codecov/default.profdata
        echo -e "${GREEN}✅ Coverage report generated${NC}"
        ;;
        
    help|*)
        echo "Usage: ./build.sh [command]"
        echo ""
        echo "Commands:"
        echo "  build     - Build with Swift PM (default)"
        echo "  test      - Run all tests"
        echo "  clean     - Remove build artifacts"
        echo "  xcode     - Generate and open Xcode project"
        echo "  ninja     - Build with Ninja generator"
        echo "  release   - Build release version"
        echo "  format    - Format Swift code"
        echo "  coverage  - Generate test coverage report"
        echo "  help      - Show this help"
        ;;
esac
