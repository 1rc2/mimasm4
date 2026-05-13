#!/bin/bash
# SM4加密工具 - Gitpod一键构建脚本

echo "======================================"
echo "SM4加密工具 - Gitpod一键构建"
echo "======================================"

# 更新系统
echo ""
echo "[1/5] 更新系统..."
sudo apt-get update -qq

# 安装依赖
echo ""
echo "[2/5] 安装编译工具..."
sudo apt-get install -y -qq python3-dev ffmpeg libsdl2-dev libsdl2-image-dev libsdl2-mixer-dev libsdl2-ttf-dev libportmidi-dev libswscale-dev libavformat-dev libavcodec-dev zlib1g-dev

echo ""
echo "[3/5] 安装Python依赖..."
pip install --upgrade pip -q
pip install buildozer kivy gmssl -q

# 创建配置
echo ""
echo "[4/5] 创建构建配置..."
cat > buildozer.spec << 'EOF'
[app]
title = SM4加密工具
package.name = sm4tool
package.domain = com.sm4crypto
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy,gmssl
orientation = portrait
fullscreen = 0
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.archs = arm64-v8a, armeabi-v7a
android.api = 27
android.minapi = 21
[buildozer]
log_level = 2
warn_on_root = 1
build_dir = ./.buildozer
bin_dir = ./bin
EOF

# 开始构建
echo ""
echo "[5/5] 开始构建APK..."
echo "这可能需要15-30分钟，请耐心等待..."
echo ""
buildozer android debug

# 查找APK
echo ""
echo "======================================"
echo "构建完成！"
echo "======================================"
echo ""
ls -la bin/*.apk 2>/dev/null || echo "未找到APK文件，请检查上方日志"
