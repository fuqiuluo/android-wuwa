#!/bin/bash

# DDK Build Script for android-wuwa kernel module
# This script uses Ylarod/ddk to build the kernel module in a containerized environment

set -e

# Default values
DEFAULT_TARGET="android12-5.10"
MODULE_NAME="android-wuwa"

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
CYAN='\033[0;36m'
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

print_success() {
    echo -e "${CYAN}[SUCCESS]${NC} $1"
}

# Localized messages
msg() {
    local key="$1"
    case "$key" in
        "usage_header")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "使用方法"
            else
                echo "Usage"
            fi
            ;;
        "description")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "使用 DDK 构建、清理和配置 android-wuwa 内核模块"
            else
                echo "Build, clean, and configure android-wuwa kernel module using DDK"
            fi
            ;;
        "commands")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "命令"
            else
                echo "Commands"
            fi
            ;;
        "build_desc")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "构建内核模块"
            else
                echo "Build kernel module"
            fi
            ;;
        "clean_desc")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "清理构建产物"
            else
                echo "Clean build artifacts"
            fi
            ;;
        "compdb_desc")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "生成 compile_commands.json（用于 IDE 支持）"
            else
                echo "Generate compile_commands.json (for IDE support)"
            fi
            ;;
        "config_desc")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "配置编译选项开关"
            else
                echo "Configure build feature flags"
            fi
            ;;
        "list_desc")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "列出已安装的 DDK 镜像"
            else
                echo "List installed DDK images"
            fi
            ;;
        "options")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "选项"
            else
                echo "Options"
            fi
            ;;
        "target_opt")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "DDK 目标（默认：android12-5.10）"
            else
                echo "DDK target (default: android12-5.10)"
            fi
            ;;
        "strip_opt")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "裁剪调试符号以减小文件大小"
            else
                echo "Strip debug symbols to reduce file size"
            fi
            ;;
        "examples")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "示例"
            else
                echo "Examples"
            fi
            ;;
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
        "strip")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "裁剪"
            else
                echo "Strip"
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
        "no_images")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "无已安装的镜像"
            else
                echo "No installed images"
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
        "clean_complete")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "清理完成！"
            else
                echo "Clean completed!"
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
        "stripping")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "正在裁剪调试符号..."
            else
                echo "Stripping debug symbols..."
            fi
            ;;
        "size_after_strip")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "裁剪后大小"
            else
                echo "Size after stripping"
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
        "generating_compdb")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "正在生成 compile_commands.json..."
            else
                echo "Generating compile_commands.json..."
            fi
            ;;
        "compdb_success")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "compile_commands.json 生成成功！"
            else
                echo "compile_commands.json generated successfully!"
            fi
            ;;
        "compdb_failed")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "生成 compile_commands.json 失败！"
            else
                echo "Failed to generate compile_commands.json!"
            fi
            ;;
        "config_title")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "配置编译选项"
            else
                echo "Configure Build Features"
            fi
            ;;
        "current_config")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "当前配置："
            else
                echo "Current configuration:"
            fi
            ;;
        "enable")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "启用"
            else
                echo "Enabled"
            fi
            ;;
        "disable")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "禁用"
            else
                echo "Disabled"
            fi
            ;;
        "toggle_prompt")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "输入编号切换开关，输入 's' 保存并退出，输入 'q' 不保存退出："
            else
                echo "Enter number to toggle, 's' to save and exit, 'q' to quit without saving:"
            fi
            ;;
        "invalid_choice")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "无效的选择"
            else
                echo "Invalid choice"
            fi
            ;;
        "config_saved")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "配置已保存！"
            else
                echo "Configuration saved!"
            fi
            ;;
        "config_cancelled")
            if [[ "$LANG_MODE" == "zh" ]]; then
                echo "配置取消，未保存更改。"
            else
                echo "Configuration cancelled, no changes saved."
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
        echo "     sudo $0 $*"
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
$(msg "usage_header"): $0 <command> [options]

$(msg "description")

$(msg "commands"):
  build [target]    $(msg "build_desc")
  clean [target]    $(msg "clean_desc")
  compdb [target]   $(msg "compdb_desc")
  config            $(msg "config_desc")
  list              $(msg "list_desc")

$(msg "options"):
  -t, --target      $(msg "target_opt")
  -s, --strip       $(msg "strip_opt")
  -h, --help        Show this help message

$(msg "examples"):
  $0 build                          # Build with default target
  $0 build android14-6.1            # Build for specific target
  $0 build -t android14-6.1 --strip # Build and strip debug symbols
  $0 clean android12-5.10           # Clean specific target
  $0 compdb                         # Generate compile_commands.json
  $0 config                         # Configure build features
  $0 list                           # List installed DDK images

Available targets: https://github.com/Ylarod/ddk/pkgs/container/ddk/versions

EOF
}

# Strip ko file
strip_module() {
    local module_file="$1"

    if [ ! -f "$module_file" ]; then
        print_error "$(msg "module_not_found")"
        return 1
    fi

    print_info "$(msg "stripping")"
    local size_before=$(du -h "$module_file" | cut -f1)

    # Get absolute path for docker volume mount
    local abs_path=$(realpath "$module_file")
    local dir_path=$(dirname "$abs_path")
    local file_name=$(basename "$abs_path")

    # Get the DDK image name
    local image_name="ghcr.io/ylarod/ddk:$TARGET"

    # Check if image exists
    if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "$image_name"; then
        # Fallback to host strip if available
        if command -v llvm-strip &> /dev/null; then
            llvm-strip -d "$module_file"
        elif command -v strip &> /dev/null; then
            strip -d "$module_file"
        else
            print_warn "strip/llvm-strip not found, skipping..."
            return 0
        fi
    else
        # Use docker run to execute strip in container
        docker run --rm -v "$dir_path:/work" "$image_name" llvm-strip -d "/work/$file_name" 2>/dev/null || \
        docker run --rm -v "$dir_path:/work" "$image_name" strip -d "/work/$file_name" 2>/dev/null || {
            # Fallback to host strip
            if command -v llvm-strip &> /dev/null; then
                llvm-strip -d "$module_file"
            elif command -v strip &> /dev/null; then
                strip -d "$module_file"
            else
                print_warn "strip/llvm-strip not found, skipping..."
                return 0
            fi
        }
    fi

    local size_after=$(du -h "$module_file" | cut -f1)
    print_success "$(msg "size_after_strip"): $size_before -> $size_after"
}

# Build module
cmd_build() {
    local TARGET="$DEFAULT_TARGET"
    local STRIP_MODULE=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -s|--strip)
                STRIP_MODULE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done

    print_info "DDK Build Script for android-wuwa"
    echo ""

    # Check prerequisites
    check_ddk_installed
    check_docker_permission

    # Display build configuration
    print_info "$(msg "build_config")"
    echo "  $(msg "target"): $TARGET"
    echo "  $(msg "module"): $MODULE_NAME.ko"
    echo "  $(msg "strip"): $([ "$STRIP_MODULE" = true ] && echo "$(msg "enable")" || echo "$(msg "disable")")"
    echo ""

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
        print_success "$(msg "build_success")"
        print_info "$(msg "output"): $MODULE_NAME.ko"
        echo ""

        # Check if the module was built
        if [ -f "$MODULE_NAME.ko" ]; then
            MODULE_SIZE=$(du -h "$MODULE_NAME.ko" | cut -f1)
            print_info "$(msg "module_size"): $MODULE_SIZE"

            # Strip if requested
            if [ "$STRIP_MODULE" = true ]; then
                strip_module "$MODULE_NAME.ko"
            fi

            # Display module info
            if command -v modinfo &> /dev/null; then
                echo ""
                print_info "$(msg "module_info")"
                modinfo "$MODULE_NAME.ko" 2>/dev/null || true
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

# Clean build artifacts
cmd_clean() {
    local TARGET="${1:-$DEFAULT_TARGET}"

    check_ddk_installed
    check_docker_permission

    print_info "$(msg "cleaning")"
    echo "  $(msg "target"): $TARGET"
    echo ""

    ddk clean --target "$TARGET"

    print_success "$(msg "clean_complete")"
}

# Generate compile_commands.json
cmd_compdb() {
    local TARGET="${1:-$DEFAULT_TARGET}"

    check_ddk_installed
    check_docker_permission

    print_info "$(msg "generating_compdb")"
    echo "  $(msg "target"): $TARGET"
    echo ""

    # Get the DDK image name
    local image_name="ghcr.io/ylarod/ddk:$TARGET"

    # Check if image exists, pull if needed
    if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "$image_name"; then
        print_warn "$(msg "image_not_found")"
        ddk pull "$TARGET" || {
            print_error "$(msg "pull_failed") $TARGET"
            exit 1
        }
    fi

    # Get current directory
    local current_dir=$(pwd)

    # Run make compdb in container
    if docker run --rm -v "$current_dir:/build" -w /build "$image_name" make compdb KDIR=\$KERNEL_SRC; then
        print_success "$(msg "compdb_success")"
    else
        print_error "$(msg "compdb_failed")"
        exit 1
    fi
}

# List installed images
cmd_list() {
    check_ddk_installed
    check_docker_permission

    print_info "$(msg "installed_images")"
    echo ""

    if ddk list 2>/dev/null; then
        echo ""
    else
        echo "  $(msg "no_images")"
        echo ""
    fi
}

# Main entry point
main() {
    if [ $# -eq 0 ]; then
        usage
        exit 0
    fi

    local command="$1"
    shift

    case "$command" in
        build)
            cmd_build "$@"
            ;;
        clean)
            cmd_clean "$@"
            ;;
        compdb)
            cmd_compdb "$@"
            ;;
        list)
            cmd_list "$@"
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            print_error "Unknown command: $command"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
