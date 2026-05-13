"""
SM4 国密加密工具 - 手机独立版
可以直接在手机上使用Python编辑器运行
"""

import sys
import os

def main():
    print("=" * 60)
    print("SM4 国密加密解密工具 v1.0")
    print("遵循 GB/T 32907-2016 标准")
    print("=" * 60)
    print()

    try:
        from sm4_final import (
            sm4_encrypt, sm4_decrypt,
            generate_random_key, generate_random_iv,
            bytes_to_hex, hex_to_bytes,
            bytes_to_base64, base64_to_bytes,
            validate_key, validate_iv
        )
        print("[OK] SM4 模块加载成功")
    except ImportError as e:
        print("[ERROR] 无法导入 SM4 模块")
        print("请确保 sm4_final.py 文件在同一目录下")
        print()
        print("错误详情:", str(e))
        input("\n按回车键退出...")
        return

    while True:
        print()
        print("=" * 60)
        print("功能菜单")
        print("=" * 60)
        print("1. 文本加密")
        print("2. 文本解密")
        print("3. 文件加密")
        print("4. 文件解密")
        print("5. 使用说明")
        print("6. 安全提示")
        print("0. 退出程序")
        print("=" * 60)

        choice = input("\n请选择功能 (0-6): ").strip()

        if choice == '1':
            encrypt_text_menu()
        elif choice == '2':
            decrypt_text_menu()
        elif choice == '3':
            encrypt_file_menu()
        elif choice == '4':
            decrypt_file_menu()
        elif choice == '5':
            show_help()
        elif choice == '6':
            show_security_tips()
        elif choice == '0':
            print("\n感谢使用！再见！")
            break
        else:
            print("\n无效选择，请重新输入")

        input("\n按回车键继续...")


def encrypt_text_menu():
    """文本加密菜单"""
    print("\n" + "=" * 60)
    print("文本加密")
    print("=" * 60)

    key = get_key_input("加密密钥")
    mode = get_mode_input()

    iv = None
    if mode != 'ECB':
        iv = get_iv_input()

    padding = get_padding_choice()
    encoding = get_encoding_choice()

    plaintext = input("\n请输入要加密的文本: ").strip()

    if not plaintext:
        print("[ERROR] 文本不能为空")
        return

    try:
        ciphertext = sm4_encrypt(
            key, plaintext, mode, iv, padding
        )

        if encoding == 'hex':
            output = bytes_to_hex(ciphertext)
        else:
            output = bytes_to_base64(ciphertext)

        print(f"\n[SUCCESS] 加密成功!")
        print(f"输出格式: {encoding.upper()}")
        print(f"密文:\n{output}")

        if mode != 'ECB' and iv is not None:
            print(f"\n注意: IV = {bytes_to_hex(iv)}")
            print("解密时需要使用相同的IV!")

    except Exception as e:
        print(f"\n[ERROR] 加密失败: {str(e)}")


def decrypt_text_menu():
    """文本解密菜单"""
    print("\n" + "=" * 60)
    print("文本解密")
    print("=" * 60)

    key = get_key_input("解密密钥")
    mode = get_mode_input()

    iv = None
    if mode != 'ECB':
        iv = get_iv_input()

    encoding = get_encoding_choice()

    ciphertext_str = input("\n请输入要解密的密文: ").strip()

    if not ciphertext_str:
        print("[ERROR] 密文不能为空")
        return

    try:
        if encoding == 'hex':
            ciphertext = hex_to_bytes(ciphertext_str)
        else:
            ciphertext = base64_to_bytes(ciphertext_str)

        plaintext = sm4_decrypt(key, ciphertext, mode, iv)

        print(f"\n[SUCCESS] 解密成功!")
        print(f"原文:\n{plaintext.decode('utf-8', errors='ignore')}")

    except Exception as e:
        print(f"\n[ERROR] 解密失败: {str(e)}")


def encrypt_file_menu():
    """文件加密菜单"""
    print("\n" + "=" * 60)
    print("文件加密")
    print("=" * 60)

    key = get_key_input("加密密钥")
    mode = get_mode_input()

    iv = None
    if mode != 'ECB':
        iv = get_iv_input()

    input_file = input("\n请输入要加密的文件路径: ").strip()

    if not os.path.exists(input_file):
        print(f"[ERROR] 文件不存在: {input_file}")
        return

    output_file = input("请输入输出文件路径: ").strip()

    if not output_file:
        print("[ERROR] 输出文件路径不能为空")
        return

    try:
        from sm4_final import sm4_encrypt_file

        sm4_encrypt_file(key, input_file, output_file, mode, iv)

        print(f"\n[SUCCESS] 文件加密成功!")
        print(f"输入文件: {input_file}")
        print(f"输出文件: {output_file}")

        if mode != 'ECB' and iv is not None:
            print(f"\n注意: IV = {bytes_to_hex(iv)}")
            print("请妥善保存，解密时需要使用!")

    except Exception as e:
        print(f"\n[ERROR] 文件加密失败: {str(e)}")


def decrypt_file_menu():
    """文件解密菜单"""
    print("\n" + "=" * 60)
    print("文件解密")
    print("=" * 60)

    key = get_key_input("解密密钥")
    mode = get_mode_input()

    iv = None
    if mode != 'ECB':
        iv = get_iv_input()

    input_file = input("\n请输入要解密的文件路径: ").strip()

    if not os.path.exists(input_file):
        print(f"[ERROR] 文件不存在: {input_file}")
        return

    output_file = input("请输入输出文件路径: ").strip()

    if not output_file:
        print("[ERROR] 输出文件路径不能为空")
        return

    try:
        from sm4_final import sm4_decrypt_file

        sm4_decrypt_file(key, input_file, output_file, mode, iv)

        print(f"\n[SUCCESS] 文件解密成功!")
        print(f"输入文件: {input_file}")
        print(f"输出文件: {output_file}")

    except Exception as e:
        print(f"\n[ERROR] 文件解密失败: {str(e)}")


def get_key_input(purpose):
    """获取密钥输入"""
    print(f"\n--- {purpose} ---")
    print("1. 随机生成密钥")
    print("2. 手动输入密钥")

    choice = input("请选择 (1-2): ").strip()

    if choice == '1':
        key = generate_random_key()
        print(f"生成的密钥 (HEX): {bytes_to_hex(key)}")
        return key
    elif choice == '2':
        key_str = input("请输入密钥 (32个十六进制字符): ").strip()
        return validate_key(key_str, 'hex')
    else:
        print("无效选择，使用随机密钥")
        return generate_random_key()


def get_iv_input():
    """获取IV输入"""
    print("\n--- IV 设置 ---")
    print("1. 随机生成IV")
    print("2. 手动输入IV")
    print("3. 不使用IV")

    choice = input("请选择 (1-3): ").strip()

    if choice == '1':
        iv = generate_random_iv()
        print(f"生成的IV (HEX): {bytes_to_hex(iv)}")
        return iv
    elif choice == '2':
        iv_str = input("请输入IV (32个十六进制字符): ").strip()
        return validate_iv(iv_str, 'hex')
    else:
        return None


def get_mode_input():
    """获取工作模式"""
    print("\n--- 工作模式 ---")
    print("1. ECB (电子密码本)")
    print("2. CBC (密码块链接) - 推荐")
    print("3. CFB (密码反馈)")
    print("4. OFB (输出反馈)")

    modes = {'1': 'ECB', '2': 'CBC', '3': 'CFB', '4': 'OFB'}
    choice = input("请选择模式 (1-4): ").strip()

    return modes.get(choice, 'CBC')


def get_padding_choice():
    """获取填充方式"""
    print("\n--- 填充方式 ---")
    print("1. PKCS7 - 推荐")
    print("2. ZeroPadding")

    choice = input("请选择 (1-2): ").strip()

    return choice == '1'


def get_encoding_choice():
    """获取编码方式"""
    print("\n--- 输出编码 ---")
    print("1. HEX (十六进制)")
    print("2. Base64")

    choice = input("请选择 (1-2): ").strip()

    return 'hex' if choice == '1' else 'base64'


def show_help():
    """显示帮助信息"""
    help_text = """
======================================================================
                              使用说明
======================================================================

1. 设置密钥：
   - 点击"随机生成密钥"自动生成16字节密钥
   - 或手动输入32个十六进制字符
   - 密钥: 0123456789abcdef0123456789abcdef

2. 选择工作模式：
   - ECB：电子密码本模式（简单，但不推荐用于长文本）
   - CBC：密码块链接模式（推荐，最常用）
   - CFB：密码反馈模式
   - OFB：输出反馈模式

3. 设置IV（初始化向量）：
   - CBC/CFB/OFB模式需要IV
   - 点击"随机生成IV"自动生成
   - IV可以公开，但每次加密应使用不同的IV

4. 选择填充方式：
   - PKCS7：自动填充到16字节边界（推荐）
   - ZeroPadding：使用零字节填充

5. 选择输出编码：
   - HEX：十六进制编码
   - Base64：Base64编码

6. 加密操作：
   - 文本模式：直接输入要加密的文本
   - 文件模式：输入文件路径进行加密

7. 解密操作：
   - 使用加密时的相同密钥
   - 使用加密时的相同模式
   - 使用加密时的相同IV（非ECB模式）
   - 使用加密时的相同填充方式

======================================================================
"""
    print(help_text)


def show_security_tips():
    """显示安全提示"""
    tips = """
======================================================================
                            安全提示
======================================================================

1. 密钥安全：
   - 妥善保管密钥，不要泄露
   - 不要通过不安全的渠道传输密钥
   - 定期更换密钥

2. 工作模式选择：
   - 推荐使用CBC模式
   - ECB模式相同明文产生相同密文，不够安全
   - 避免使用ECB加密长消息或结构化数据

3. IV使用建议：
   - 每次加密使用不同的随机IV
   - IV可以公开，但应唯一
   - IV重用会降低安全性

4. 数据保护：
   - 加密后及时删除明文文件
   - 使用安全的存储和传输方式
   - 重要数据建议离线保存

5. 离线使用：
   - 本工具完全离线运行
   - 不上传任何数据到网络
   - 适合处理敏感信息

6. 使用场景：
   - 文本加密：聊天记录、密码、敏感信息
   - 文件加密：文档、图片、视频等
   - 推荐使用CBC模式 + PKCS7填充

======================================================================
                           技术规格
======================================================================

标准: GB/T 32907-2016 (中国商用密码标准)
算法: SM4 对称加密算法
密钥长度: 128位 (16字节)
分组长度: 128位 (16字节)
工作模式: ECB, CBC, CFB, OFB
填充方式: PKCS7, ZeroPadding

======================================================================
"""
    print(tips)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        print(f"\n\n程序发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        input("\n按回车键退出...")
