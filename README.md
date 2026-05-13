# SM4国密加密工具 - 手机版

基于GB/T 32907-2016标准的SM4加密解密工具，支持在手机上直接运行。

## 功能特性

- ✅ 文本加密/解密
- ✅ 文件加密/解密  
- ✅ 支持ECB/CBC/CFB/OFB四种工作模式
- ✅ 支持PKCS7/ZeroPadding填充方式
- ✅ 随机生成密钥/IV
- ✅ 支持Hex/Base64编码输出
- ✅ 完全离线运行，不上传任何数据

## 技术规格

- **标准**: GB/T 32907-2016
- **密钥长度**: 128位（16字节）
- **分组长度**: 128位（16字节）

## 使用方法

### 方法1: 使用Pydroid 3运行

1. 在手机上安装 **Pydroid 3**（Play商店搜索）
2. 将所有Python文件发送到手机
3. 用Pydroid 3打开 `sm4_phone.py`
4. 点击运行 ▶️

### 方法2: 使用QPython运行

1. 在手机上安装 **QPython 3**
2. 将文件复制到手机
3. 在QPython中打开并运行

### 方法3: 终端运行

```bash
python sm4_phone.py
```

## 文件结构

```
├── sm4_phone.py      # 手机版主程序（命令行界面）
├── sm4_final.py      # SM4核心算法API
├── sm4_core.py       # SM4算法实现
├── sm4_modes.py      # 工作模式实现
├── sm4_utils.py      # 工具函数
└── QUICKSTART.txt    # 快速开始指南
```

## 操作说明

1. **设置密钥**: 随机生成或手动输入16字节密钥
2. **选择模式**: ECB/CBC/CFB/OFB（推荐CBC）
3. **设置IV**: CBC/CFB/OFB模式需要16字节IV
4. **选择编码**: Hex或Base64
5. **加密/解密**: 输入文本或文件路径

## 安全提示

- 密钥请勿泄露
- 推荐使用CBC模式
- 每次加密使用不同的随机IV
- 本工具完全离线运行

## 依赖

- Python 3.6+
- gmssl库（用于SM4加密）

## 安装依赖

```bash
pip install gmssl
```

## License

仅供学习和研究使用，请勿用于非法用途。

## 版本

v1.0
