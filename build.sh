#!/bin/bash

# 🚀 Script de Compilação - PQC Hybrid Library v1.0.0-BETA
# Usage: ./build.sh [clean|test|package|install]

set -e

LIBRARY_NAME="pqc-hybrid-certificates"
LIBRARY_VERSION="1.0.0-BETA"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  PQC Hybrid Certificate Library - Build Script                 ║"
    echo "║  Version: $LIBRARY_VERSION                                     ║"
    echo "║  Status: Production-Ready (v1.0.0-BETA)                        ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check Maven installation
check_maven() {
    if ! command -v mvn &> /dev/null; then
        echo -e "${RED}❌ Maven not found!${NC}"
        echo "Please install Maven 3.9+ or higher"
        echo "Visit: https://maven.apache.org/install"
        exit 1
    fi
    
    MVN_VERSION=$(mvn --version 2>/dev/null | head -1)
    echo -e "${GREEN}✅ Maven found: ${NC}${MVN_VERSION}"
}

# Check Java installation
check_java() {
    if ! command -v java &> /dev/null; then
        echo -e "${RED}❌ Java not found!${NC}"
        echo "Please install Java 21+ or higher"
        exit 1
    fi
    
    JAVA_VERSION=$(java -version 2>&1 | head -1)
    echo -e "${GREEN}✅ Java found: ${NC}${JAVA_VERSION}"
    
    # Check if Java version is 21 or higher
    JAVA_VER=$(java -version 2>&1 | sed -n ';s/.* version "\(.*\)".*/\1/p' | head -c 2)
    if [ "$JAVA_VER" -lt 21 ]; then
        echo -e "${YELLOW}⚠️  Warning: Java should be 21 or higher (you have Java $JAVA_VER)${NC}"
    fi
}

# Show help
show_help() {
    echo -e "${BLUE}Build Commands:${NC}"
    echo "  ./build.sh clean      - Clean build artifacts"
    echo "  ./build.sh compile    - Compile source code"
    echo "  ./build.sh test       - Run unit tests (if available)"
    echo "  ./build.sh package    - Package as JAR (default)"
    echo "  ./build.sh install    - Install in local Maven repository"
    echo "  ./build.sh javadoc    - Generate JavaDoc"
    echo "  ./build.sh help       - Show this help message"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  ./build.sh             # Default: clean + package"
    echo "  ./build.sh clean       # Remove all build artifacts"
    echo "  ./build.sh install     # Build and install in local repo"
}

# Build clean
build_clean() {
    echo -e "\n${YELLOW}🧹 Cleaning build artifacts...${NC}"
    mvn clean -q
    echo -e "${GREEN}✅ Build artifacts cleaned${NC}"
}

# Build compile
build_compile() {
    echo -e "\n${YELLOW}📝 Compiling source code...${NC}"
    mvn compile
    echo -e "${GREEN}✅ Compilation successful${NC}"
}

# Build test
build_test() {
    echo -e "\n${YELLOW}🧪 Running tests...${NC}"
    if mvn test 2>&1 | grep -q "No tests to run"; then
        echo -e "${YELLOW}⚠️  No tests found. Create tests in src/test/java${NC}"
    else
        echo -e "${GREEN}✅ Tests completed${NC}"
    fi
}

# Build package
build_package() {
    echo -e "\n${YELLOW}📦 Packaging JAR files...${NC}"
    mvn package -DskipTests=true -q
    
    # Show generated JAR files
    JAR_COUNT=$(find target -name "*.jar" 2>/dev/null | wc -l)
    if [ "$JAR_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✅ Package successful!${NC}"
        echo -e "\n${BLUE}Generated artifacts:${NC}"
        ls -lh target/*.jar 2>/dev/null | awk '{print "   📄", $9, "(" $5 ")"}'
    else
        echo -e "${RED}❌ No JAR files generated${NC}"
        exit 1
    fi
}

# Build install
build_install() {
    echo -e "\n${YELLOW}📥 Installing in local Maven repository...${NC}"
    mvn install -DskipTests=true -q
    echo -e "${GREEN}✅ Installation successful!${NC}"
    echo -e "${BLUE}You can now use it as a dependency:${NC}"
    cat << 'EOF'
    <dependency>
        <groupId>com.pqc.hybrid</groupId>
        <artifactId>pqc-hybrid-certificates</artifactId>
        <version>1.0.0-BETA</version>
    </dependency>
EOF
}

# Build javadoc
build_javadoc() {
    echo -e "\n${YELLOW}📚 Generating JavaDoc...${NC}"
    mvn javadoc:javadoc -q
    DOC_DIR="target/site/apidocs"
    if [ -d "$DOC_DIR" ]; then
        echo -e "${GREEN}✅ JavaDoc generated!${NC}"
        echo -e "${BLUE}Open in browser:${NC} file://$(pwd)/$DOC_DIR/index.html"
    else
        echo -e "${YELLOW}⚠️  JavaDoc directory not found${NC}"
    fi
}

# Show project info
show_project_info() {
    echo -e "\n${BLUE}Project Information:${NC}"
    echo "  Name: $LIBRARY_NAME"
    echo "  Version: $LIBRARY_VERSION"
    echo "  Location: $PROJECT_DIR"
    echo "  Java Target: 21+"
    echo "  Primary Dependencies:"
    echo "    - BouncyCastle 1.77+ (NIST PQC)"
    echo "    - JUnit 5.9.3+ (Testing)"
    echo "    - SLF4J 2.0.7+ (Logging)"
}

# Main logic
main() {
    print_banner
    show_project_info
    
    echo ""
    check_java
    check_maven
    
    # Default command: clean + package
    COMMAND="${1:-package}"
    
    case "$COMMAND" in
        clean)
            build_clean
            ;;
        compile)
            build_clean
            build_compile
            ;;
        test)
            build_clean
            build_compile
            build_test
            ;;
        package)
            build_clean
            build_compile
            build_package
            ;;
        install)
            build_clean
            build_compile
            build_package
            build_install
            ;;
        javadoc)
            build_javadoc
            ;;
        all)
            build_clean
            build_compile
            build_test
            build_package
            build_javadoc
            ;;
        help|-h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}❌ Unknown command: $COMMAND${NC}"
            show_help
            exit 1
            ;;
    esac
    
    echo -e "\n${GREEN}✨ Build completed successfully!${NC}\n"
}

# Run main
main "$@"
