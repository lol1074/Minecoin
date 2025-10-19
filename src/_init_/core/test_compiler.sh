#!/bin/bash

# Build script per Bootstrap Manager

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Bootstrap Manager - Build Script${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="Linux"
    LDFLAGS="-lpthread -ldl"
    OUTPUT="test_bootstrap"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macOS"
    LDFLAGS="-lpthread"
    OUTPUT="test_bootstrap"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    PLATFORM="Windows"
    LDFLAGS="-lpsapi -lws2_32 -liphlpapi"
    OUTPUT="test_bootstrap.exe"
else
    echo -e "${RED}Unknown platform: $OSTYPE${NC}"
    exit 1
fi

echo -e "Platform: ${YELLOW}$PLATFORM${NC}"
echo ""

# Compiler
CXX="g++"
CXXFLAGS="-std=c++17 -Wall -Wextra"

# Build type
BUILD_TYPE="${1:-release}"

if [ "$BUILD_TYPE" == "debug" ]; then
    echo -e "Build type: ${YELLOW}DEBUG${NC}"
    CXXFLAGS="$CXXFLAGS -g -O0 -D_DEBUG"
elif [ "$BUILD_TYPE" == "release" ]; then
    echo -e "Build type: ${YELLOW}RELEASE${NC}"
    CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
else
    echo -e "${RED}Invalid build type: $BUILD_TYPE${NC}"
    echo "Usage: $0 [debug|release]"
    exit 1
fi

echo ""

# Clean previous build
if [ -f "$OUTPUT" ]; then
    echo -e "${YELLOW}Cleaning previous build...${NC}"
    rm -f "$OUTPUT" *.o
    echo "Done"
    echo ""
fi

# Compile bootstrap_manager.cpp
echo -e "${GREEN}Compiling bootstrap_manager.cpp...${NC}"
$CXX $CXXFLAGS -c bootstrap_manager.cpp -o bootstrap_manager.o
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Success${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi
echo ""

# Compile test_bootstrap_manager.cpp
echo -e "${GREEN}Compiling test_bootstrap_manager.cpp...${NC}"
$CXX $CXXFLAGS -c test_bootstrap_manager.cpp -o test_bootstrap_manager.o
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Success${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi
echo ""

# Link
echo -e "${GREEN}Linking $OUTPUT...${NC}"
$CXX $CXXFLAGS -o $OUTPUT bootstrap_manager.o test_bootstrap_manager.o $LDFLAGS
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Success${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
    exit 1
fi
echo ""

# Get file size
if [ -f "$OUTPUT" ]; then
    SIZE=$(du -h "$OUTPUT" | cut -f1)
    echo -e "${GREEN}Build complete!${NC}"
    echo -e "Output: ${YELLOW}$OUTPUT${NC} ($SIZE)"
    echo ""
    
    # Ask to run
    read -p "Run test now? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${GREEN}Running test...${NC}"
        echo ""
        ./$OUTPUT
    fi
else
    echo -e "${RED}Build failed - output file not found${NC}"
    exit 1
fi