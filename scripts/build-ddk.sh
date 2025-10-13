#!/bin/bash

# DDK Build Script for android-wuwa kernel module
# This script uses Ylarod/ddk to build the kernel module in a containerized environment

set -e

# Default target
DEFAULT_TARGET="android12-5.10"
TARGET="${1:-$DEFAULT_TARGET}"

# Detect system language
if [[ "$LANG" =~ ^zh ]]; then
    LANG_MODE="zh"
else
    LANG_MODE="en"
fi

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored message
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Localized messages
msg() {
    local key="$1"
    case "$key" in
        "ddk_not_installed")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "ddk 未安装！"
            else
                echo "ddk is not installed!"
            fi
            ;;
        "install_ddk")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "请先安装 ddk："
            else
                echo "Please install ddk first:"
            fi
            ;;
        "more_info")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "更多信息，请访问："
            else
                echo "For more information, visit:"
            fi
            ;;
        "docker_not_installed")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "Docker 未安装！"
            else
                echo "Docker is not installed!"
            fi
            ;;
        "docker_required")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "DDK 需要 Docker 才能运行。请先安装 Docker："
            else
                echo "DDK requires Docker to run. Please install Docker first:"
            fi
            ;;
        "docker_permission_error")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "无法访问 Docker 守护进程！"
            else
                echo "Cannot access Docker daemon!"
            fi
            ;;
        "docker_needs_root")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "Docker 在此系统上需要 root 权限。"
            else
                echo "Docker requires root privileges on this system."
            fi
            ;;
        "solutions")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "解决方案："
            else
                echo "Solutions:"
            fi
            ;;
        "run_with_sudo")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "使用 sudo 运行此脚本："
            else
                echo "Run this script with sudo:"
            fi
            ;;
        "add_to_docker_group")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "将您的用户添加到 docker 组（需要注销/登录）："
            else
                echo "Add your user to the docker group (requires logout/login):"
            fi
            ;;
        "build_config")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "构建配置："
            else
                echo "Build Configuration:"
            fi
            ;;
        "target")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "目标"
            else
                echo "Target"
            fi
            ;;
        "module")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "模块"
            else
                echo "Module"
            fi
            ;;
        "checking_image")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "检查 DDK 镜像："
            else
                echo "Checking DDK image for target:"
            fi
            ;;
        "installed_images")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "已安装的镜像："
            else
                echo "Installed images:"
            fi
            ;;
        "image_not_found")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "镜像未在本地找到，正在从仓库拉取..."
            else
                echo "Image not found locally, pulling from registry..."
            fi
            ;;
        "pull_failed")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "拉取镜像失败："
            else
                echo "Failed to pull image for target:"
            fi
            ;;
        "check_target")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "请检查目标是否存在："
            else
                echo "Please check if the target exists:"
            fi
            ;;
        "cleaning")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "清理之前的构建产物..."
            else
                echo "Cleaning previous build artifacts..."
            fi
            ;;
        "building")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "正在构建内核模块..."
            else
                echo "Building kernel module..."
            fi
            ;;
        "build_success")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "构建成功！"
            else
                echo "Build successful!"
            fi
            ;;
        "output")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "输出"
            else
                echo "Output"
            fi
            ;;
        "module_size")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "模块大小"
            else
                echo "Module size"
            fi
            ;;
        "module_info")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "模块信息："
            else
                echo "Module information:"
            fi
            ;;
        "module_not_found")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "模块文件未找到，但构建报告成功"
            else
                echo "Module file not found, but build reported success"
            fi
            ;;
        "build_failed")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "构建失败！"
            else
                echo "Build failed!"
            fi
            ;;
        "common_issues")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "常见问题："
            else
                echo "Common issues:"
            fi
            ;;
        "issue_1")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "不兼容的内核目标 - 检查可用目标"
            else
                echo "Incompatible kernel target - check available targets"
            fi
            ;;
        "issue_2")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "Makefile 中缺少依赖"
            else
                echo "Missing dependencies in Makefile"
            fi
            ;;
        "issue_3")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "源代码中的语法错误"
            else
                echo "Syntax errors in source code"
            fi
            ;;
        "check_log")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "检查上面的构建日志以获取详细信息。"
            else
                echo "Check the build log above for details."
            fi
            ;;
    esac
}

# Check if ddk is installed
check_ddk_installed() {
    if ! command -v ddk &> /dev/null; then
        print_error "$(msg "ddk_not_installed")"
        echo ""
        echo "$(msg "install_ddk")"
        echo "  sudo curl -fsSL https://raw.githubusercontent.com/Ylarod/ddk/main/scripts/ddk -o /usr/local/bin/ddk"
        echo "  sudo chmod +x /usr/local/bin/ddk"
        echo ""
        echo "$(msg "more_info") https://github.com/Ylarod/ddk"
        exit 1
    fi
}

# Check docker permissions
check_docker_permission() {
    if ! command -v docker &> /dev/null; then
        print_error "$(msg "docker_not_installed")"
        echo ""
        echo "$(msg "docker_required")"
        echo "  https://docs.docker.com/engine/install/"
        exit 1
    fi

    # Try to run docker without sudo
    if ! docker info &> /dev/null; then
        print_error "$(msg "docker_permission_error")"
        echo ""
        echo "$(msg "docker_needs_root")"
        echo ""
        echo "$(msg "solutions")"
        echo "  1. $(msg "run_with_sudo")"
        echo "     sudo $0 $TARGET"
        echo ""
        echo "  2. $(msg "add_to_docker_group")"
        echo "     sudo usermod -aG docker \$USER"
        echo "     newgrp docker"
        echo ""
        exit 1
    fi
}

# Display usage
usage() {
    cat << EOF
Usage: $0 [TARGET]

Build android-wuwa kernel module using DDK (Kernel Driver Development Kit)

Arguments:
  TARGET    Kernel version target (default: $DEFAULT_TARGET)
            Examples: android12-5.10, android13-5.15, android14-6.1, android16-6.12
            Full list: https://github.com/Ylarod/ddk/pkgs/container/ddk/versions

Examples:
  $0                      # Build with default target ($DEFAULT_TARGET)
  $0 android14-6.1        # Build for Android 14 with kernel 6.1
  $0 android16-6.12       # Build for Android 16 with kernel 6.12

Note: This script requires Docker. On some systems, you may need to run with sudo.

EOF
}

# Main build function
main() {
    # Parse help flag
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        usage
        exit 0
    fi

    print_info "DDK Build Script for android-wuwa"
    echo ""

    # Check if ddk is installed
    check_ddk_installed

    # Check docker permissions
    check_docker_permission

    # Display build configuration
    print_info "$(msg "build_config")"
    echo "  $(msg "target"): $TARGET"
    echo "  $(msg "module"): android-wuwa.ko"
    echo ""

    # List installed images
    print_info "$(msg "installed_images")"
    if ddk list 2>/dev/null; then
        echo ""
    else
        if [[ "$LANG_MODE" == "zh" ]]; then
            echo "  无已安装的镜像"
        else
            echo "  No installed images"
        fi
        echo ""
    fi

    # Pull image if needed
    print_info "$(msg "checking_image") $TARGET"
    if ! ddk list 2>/dev/null | grep -q "$TARGET"; then
        print_warn "$(msg "image_not_found")"
        ddk pull "$TARGET" || {
            print_error "$(msg "pull_failed") $TARGET"
            echo ""
            echo "$(msg "check_target")"
            echo "  https://github.com/Ylarod/ddk/pkgs/container/ddk/versions"
            exit 1
        }
    fi

    # Clean previous build
    print_info "$(msg "cleaning")"
    ddk clean --target "$TARGET" 2>/dev/null || true

    # Build the module
    print_info "$(msg "building")"
    echo ""

    if ddk build --target "$TARGET"; then
        echo ""
        print_info "$(msg "build_success")"
        print_info "$(msg "output"): android-wuwa.ko"
        echo ""

        # Check if the module was built
        if [ -f "android-wuwa.ko" ]; then
            MODULE_SIZE=$(du -h android-wuwa.ko | cut -f1)
            print_info "$(msg "module_size"): $MODULE_SIZE"

            # Display module info
            if command -v modinfo &> /dev/null; then
                echo ""
                print_info "$(msg "module_info")"
                modinfo android-wuwa.ko 2>/dev/null || true
            fi
        else
            print_warn "$(msg "module_not_found")"
        fi
        echo ""
    else
        echo ""
        print_error "$(msg "build_failed")"
        echo ""
        echo "$(msg "common_issues")"
        echo "  1. $(msg "issue_1")"
        echo "  2. $(msg "issue_2")"
        echo "  3. $(msg "issue_3")"
        echo ""
        echo "$(msg "check_log")"
        exit 1
    fi
}

# Run main function
main "$@"
