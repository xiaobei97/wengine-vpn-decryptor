from Crypto.Cipher import AES
import re
import urllib.parse

def extract_encrypted_part(webvpn_url):
    """
    从完整的WebVPN URL中提取加密部分
    
    Args:
        webvpn_url (str): 完整的WebVPN URL
    
    Returns:
        tuple: (加密的十六进制字符串, 原始URL的路径部分)
    """
    # 匹配加密部分和后续路径的模式
    patterns = [
        # 匹配类似 /https/加密字符串/portal 的格式
        r'/(?:https?|http-?\d*)/([0-9a-fA-F]+)(/.*)?',
        # 匹配其他协议格式
        r'/(?:tcp|udp|ssh|rdp|vnc|telnet)-?\d*/([0-9a-fA-F]+)(/.*)?'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, webvpn_url)
        if match:
            encrypted_part = match.group(1)
            path_part = match.group(2) if match.group(2) else ""
            return encrypted_part, path_part
    
    # 如果没有匹配到模式，尝试直接提取
    hex_pattern = r'/([0-9a-fA-F]{32,})(/.*)?'
    match = re.search(hex_pattern, webvpn_url)
    if match:
        encrypted_part = match.group(1)
        path_part = match.group(2) if match.group(2) else ""
        return encrypted_part, path_part
    
    return None, ""

def decrypt_webvpn_url(encrypted_hex, key, iv):
    """
    解密WebVPN的加密URL
    
    Args:
        encrypted_hex (str): 加密的十六进制字符串
        key (str): 加密密钥
        iv (str): 初始化向量
    
    Returns:
        str: 解密后的原始URL
    """
    # 将密钥和IV转换为字节
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    
    # 提取IV和密文（前32字符是IV的十六进制表示）
    iv_hex = encrypted_hex[:32]
    ciphertext_hex = encrypted_hex[32:]
    
    # 将十六进制转换为字节
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    
    # 使用AES-CFB模式解密（segment_size=128表示CFB8模式）
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv=iv_bytes, segment_size=128)
    decrypted_data = cipher.decrypt(ciphertext_bytes)
    
    # 返回解密后的URL
    return decrypted_data.decode('utf-8')

def print_separator():
    """打印分隔线"""
    print("=" * 60)

def print_sub_separator():
    """打印子分隔线"""
    print("-" * 60)

def parse_and_display_url(url, webvpn_path):
    """
    解析并显示URL的各个组件
    
    Args:
        url (str): 解密后的URL
        webvpn_path (str): WebVPN URL中的路径部分
    """
    try:
        # 如果解密后的URL不包含协议，添加默认的http://
        if not url.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            display_url = url
            parsed_url = urllib.parse.urlparse('http://' + url)
        else:
            display_url = url
            parsed_url = urllib.parse.urlparse(url)
        
        print(f"解密后的URL: {display_url}")
        
        if parsed_url.scheme:
            print(f"协议: {parsed_url.scheme}")
        if parsed_url.netloc:
            print(f"域名: {parsed_url.netloc}")
        if parsed_url.path and parsed_url.path != "/":
            print(f"路径: {parsed_url.path}")
        if parsed_url.query:
            print(f"查询参数: {parsed_url.query}")
        
        # 显示WebVPN URL中的路径部分（如/portal）
        if webvpn_path:
            print(f"WebVPN路径: {webvpn_path}")
            
    except Exception as e:
        print(f"URL解析错误: {e}")
        print(f"解密后的URL: {url}")
        if webvpn_path:
            print(f"WebVPN路径: {webvpn_path}")

def main():
    print_separator()
    print("Wengine-VPN URL 解密工具")
    print_separator()
    
    # 固定的密钥和IV（根据您提供的）
    key = "b0A58a69394ce73@"
    iv = "b0A58a69394ce73@"
    
    print(f"使用密钥: {key}")
    print(f"使用IV: {iv}")
    print_sub_separator()
    
    while True:
        try:
            # 获取用户输入
            webvpn_url = input("\n请输入WebVPN URL（输入 'quit' 退出）: ").strip()
            
            if webvpn_url.lower() in ['quit', 'exit', 'q']:
                print("感谢使用，再见！")
                break
            
            if not webvpn_url:
                print("请输入有效的URL！")
                continue
            
            # 提取加密部分和路径部分
            encrypted_part, webvpn_path = extract_encrypted_part(webvpn_url)
            
            if not encrypted_part:
                print("无法从URL中提取加密部分，请检查URL格式")
                print("支持的格式示例:")
                print("  - https://webvpn.neu.edu.cn/https/62304135386136393339346365373340a0e4b62c85cb47d1bc166e66c800d19283ef83")
                print("  - https://webvpn.neu.edu.cn/http-8080/62304135386136393339346365373340a0e4b62c85cb47d1bc166e66c800d19283ef83/portal")
                continue
            
            print(f"提取的加密部分: {encrypted_part}")
            print(f"加密部分长度: {len(encrypted_part)} 字符")
            if webvpn_path:
                print(f"WebVPN路径部分: {webvpn_path}")
            
            # 检查加密部分长度
            if len(encrypted_part) < 32:
                print("加密部分太短，可能不是有效的加密数据")
                continue
            
            # 尝试解密
            try:
                decrypted_url = decrypt_webvpn_url(encrypted_part, key, iv)
                print("\n" + "=" * 60)
                print("✅ 解密成功！")
                print_separator()
                print(f"原始WebVPN URL: {webvpn_url}")
                
                # 解析并显示URL组件
                parse_and_display_url(decrypted_url, webvpn_path)
                
            except Exception as e:
                print(f"\n❌ 解密失败: {e}")
                print("可能的原因:")
                print("  - 加密部分格式不正确")
                print("  - 密钥/IV不匹配")
                print("  - URL可能使用了不同的加密方式")
        
        except KeyboardInterrupt:
            print("\n\n程序被用户中断")
            break
        except Exception as e:
            print(f"发生错误: {e}")

if __name__ == "__main__":
    main()
