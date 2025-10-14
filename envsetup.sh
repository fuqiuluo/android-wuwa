export DDK_ROOT=/opt/ddk

export KERNEL_SRC=$DDK_ROOT/kdir/android12-5.10
export CLANG_PATH=$DDK_ROOT/clang/clang-r416183b/bin

# export KERNEL_SRC=$DDK_ROOT/kdir/android13-5.15
# export CLANG_PATH=$DDK_ROOT/clang/clang-r450784e/bin

# export KERNEL_SRC=$DDK_ROOT/kdir/android14-6.1
# export CLANG_PATH=$DDK_ROOT/clang/clang-r487747c/bin

# export CLANG_PATH=/home/ylarod/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/bin
export PATH=$CLANG_PATH:$PATH
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64
export LLVM=1
export LLVM_IAS=1
