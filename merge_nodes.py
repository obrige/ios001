#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
import re
import json
import socket
import urllib.parse
import urllib.request
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 国家代码到 emoji 的映射
COUNTRY_EMOJI = {
    'CN': '🇨🇳', 'US': '🇺🇸', 'JP': '🇯🇵', 'KR': '🇰🇷', 'HK': '🇭🇰',
    'TW': '🇹🇼', 'SG': '🇸🇬', 'GB': '🇬🇧', 'DE': '🇩🇪', 'FR': '🇫🇷',
    'CA': '🇨🇦', 'AU': '🇦🇺', 'RU': '🇷🇺', 'IN': '🇮🇳', 'BR': '🇧🇷',
    'NL': '🇳🇱', 'SE': '🇸🇪', 'CH': '🇨🇭', 'IT': '🇮🇹', 'ES': '🇪🇸',
    'PL': '🇵🇱', 'TR': '🇹🇷', 'MY': '🇲🇾', 'TH': '🇹🇭', 'VN': '🇻🇳',
    'ID': '🇮🇩', 'PH': '🇵🇭', 'AR': '🇦🇷', 'MX': '🇲🇽', 'CL': '🇨🇱',
    'FI': '🇫🇮', 'NO': '🇳🇴', 'DK': '🇩🇰', 'BE': '🇧🇪', 'AT': '🇦🇹',
    'IE': '🇮🇪', 'NZ': '🇳🇿', 'ZA': '🇿🇦', 'AE': '🇦🇪', 'SA': '🇸🇦',
    'IL': '🇮🇱', 'EG': '🇪🇬', 'NG': '🇳🇬', 'KE': '🇰🇪', 'UA': '🇺🇦',
    'RO': '🇷🇴', 'CZ': '🇨🇿', 'PT': '🇵🇹', 'GR': '🇬🇷', 'HU': '🇭🇺',
    'BG': '🇧🇬', 'HR': '🇭🇷', 'SK': '🇸🇰', 'LT': '🇱🇹', 'LV': '🇱🇻',
    'EE': '🇪🇪', 'IS': '🇮🇸', 'LU': '🇱🇺', 'MT': '🇲🇹', 'CY': '🇨🇾',
    'MO': '🇲🇴', 'BD': '🇧🇩', 'PK': '🇵🇰', 'LK': '🇱🇰', 'MM': '🇲🇲',
    'KH': '🇰🇭', 'LA': '🇱🇦', 'NP': '🇳🇵', 'MN': '🇲🇳', 'KZ': '🇰🇿',
    'UZ': '🇺🇿', 'GE': '🇬🇪', 'AM': '🇦🇲', 'AZ': '🇦🇿', 'BY': '🇧🇾',
    'MD': '🇲🇩', 'RS': '🇷🇸', 'BA': '🇧🇦', 'AL': '🇦🇱', 'MK': '🇲🇰',
    'SI': '🇸🇮', 'ME': '🇲🇪', 'XK': '🇽🇰', 'LI': '🇱🇮', 'MC': '🇲🇨',
    'SM': '🇸🇲', 'VA': '🇻🇦', 'AD': '🇦🇩', 'JO': '🇯🇴', 'LB': '🇱🇧',
    'IQ': '🇮🇶', 'SY': '🇸🇾', 'YE': '🇾🇪', 'OM': '🇴🇲', 'KW': '🇰🇼',
    'BH': '🇧🇭', 'QA': '🇶🇦', 'PS': '🇵🇸', 'AF': '🇦🇫', 'IR': '🇮🇷',
}

def is_base64(s):
    """检查字符串是否为有效的 base64"""
    try:
        if isinstance(s, str):
            s = s.strip()
            if len(s) < 4:
                return False
            sb_bytes = bytes(s, 'ascii')
        elif isinstance(s, bytes):
            sb_bytes = s
        else:
            return False
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False

def decode_base64(content):
    """解码 base64 内容"""
    try:
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        return decoded
    except Exception as e:
        return None

def is_valid_node(line):
    """检查是否为有效的节点链接"""
    protocols = ['ss://', 'vmess://', 'vless://', 'trojan://', 'trojan-go://', 
                 'hysteria://', 'hysteria2://', 'hy2://', 'tuic://', 'shadowsocks://']
    return any(line.startswith(prefix) for prefix in protocols)

def is_ipv6(host):
    """检查是否为 IPv6 地址"""
    # 去掉可能的中括号
    host = host.strip('[]')
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except:
        return False

def is_ipv4(host):
    """检查是否为 IPv4 地址"""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except:
        return False

def is_domain(host):
    """检查是否为域名"""
    return not is_ipv4(host) and not is_ipv6(host)

def resolve_domain_to_ip(host):
    """将域名解析为 IP 地址"""
    try:
        # 优先尝试 IPv4
        addr_info = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        if addr_info:
            return addr_info[0][4][0]
    except:
        pass
    
    try:
        # 尝试 IPv6
        addr_info = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
        if addr_info:
            return addr_info[0][4][0]
    except:
        pass
    
    return None

def query_ip_info(ip, retries=3):
    """查询 IP 地理位置信息"""
    if not ip:
        return None
    
    # 去掉 IPv6 的中括号（如果有）
    ip = ip.strip('[]')
    
    for attempt in range(retries):
        try:
            url = f"https://ipgeo-api.hf.space/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
            else:
                print(f"    ⚠ IP查询失败: {ip} - {e}")
    
    return None

def get_country_emoji(country_code):
    """根据国家代码获取 emoji"""
    return COUNTRY_EMOJI.get(country_code.upper(), '🌐')

def generate_node_label(ip_info, ip):
    """根据 IP 信息生成节点标签"""
    if not ip_info:
        return f"🌐|Unknown-{ip}"
    
    parts = []
    
    # 获取国家代码和 emoji
    country_code = ip_info.get('country', {}).get('code', '')
    country_name = ip_info.get('country', {}).get('name', '')
    
    if country_code:
        emoji = get_country_emoji(country_code)
        parts.append(emoji)
    
    if country_name:
        parts.append(country_name)
    
    # 运营商
    as_info = ip_info.get('as', {}).get('info', '')
    if as_info:
        parts.append(as_info)
    
    # 地区
    regions_short = ip_info.get('regions_short', [])
    if regions_short:
        parts.append('-'.join(regions_short))
    
    # 类型
    ip_type = ip_info.get('type', '')
    if ip_type:
        parts.append(ip_type)
    
    # 判断是否为原生IP
    registered_country = ip_info.get('registered_country', {}).get('code', '')
    country_code_check = ip_info.get('country', {}).get('code', '')
    
    if registered_country and country_code_check:
        if registered_country == country_code_check:
            parts.append('原生IP')
        else:
            parts.append('广播IP')
    
    label = '|'.join(parts) if parts else f"🌐|Unknown-{ip}"
    return label

def parse_node_address(node_url):
    """解析节点地址和端口"""
    try:
        if node_url.startswith('ss://'):
            parts = node_url[5:].split('#')[0].split('@')
            if len(parts) == 2:
                server_info = parts[1].split(':')
                if len(server_info) >= 2:
                    host = server_info[0].strip('[]')
                    port = int(server_info[1].split('?')[0].split('/')[0])
                    return host, port
            else:
                decoded = decode_base64(parts[0].split('#')[0])
                if decoded and '@' in decoded:
                    server_info = decoded.split('@')[1].split(':')
                    if len(server_info) >= 2:
                        host = server_info[0].strip('[]')
                        port = int(server_info[1])
                        return host, port
        
        elif node_url.startswith('vmess://'):
            vmess_data = node_url[8:].split('#')[0]
            decoded = decode_base64(vmess_data)
            if decoded:
                config = json.loads(decoded)
                host = config.get('add', '').strip('[]')
                port = int(config.get('port', 0))
                return host, port
        
        elif node_url.startswith('vless://'):
            parsed = urllib.parse.urlparse(node_url)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return host, port
        
        elif node_url.startswith('trojan://') or node_url.startswith('trojan-go://'):
            parsed = urllib.parse.urlparse(node_url)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return host, port
        
        elif node_url.startswith('hysteria://') or node_url.startswith('hysteria2://') or node_url.startswith('hy2://'):
            parsed = urllib.parse.urlparse(node_url)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return host, port
        
        elif node_url.startswith('tuic://'):
            parsed = urllib.parse.urlparse(node_url)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return host, port
                
    except Exception as e:
        pass
    
    return None, None

def tcp_ping(host, port, timeout=1):
    """TCP ping 检测，自动支持 IPv4 和 IPv6，超时1秒"""
    if not host or not port:
        return False
    
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        for family, socktype, proto, canonname, sockaddr in addr_info:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                sock.close()
                return True
            except:
                continue
        
        return False
    except Exception as e:
        return False

def update_node_label(node_url, new_label):
    """更新节点的标签"""
    # 移除原有标签
    if '#' in node_url:
        node_url = node_url.split('#')[0]
    
    # 添加新标签（URL 编码）
    encoded_label = urllib.parse.quote(new_label)
    return f"{node_url}#{encoded_label}"

def normalize_ipv6_in_url(node_url, host, port):
    """将节点 URL 中的 IPv6 地址标准化为 [host]:port 格式"""
    # 只处理 IPv6 地址，不处理域名
    if not is_ipv6(host):
        return node_url
    
    try:
        # 对于不同协议，处理方式不同
        if node_url.startswith('ss://'):
            # SS 协议需要特殊处理
            parts = node_url.split('@')
            if len(parts) == 2:
                before_at = parts[0]
                after_at = parts[1]
                
                # 替换 host:port 为 [host]:port
                if '#' in after_at:
                    server_part, label_part = after_at.split('#', 1)
                    new_url = f"{before_at}@[{host}]:{port}#{label_part}"
                else:
                    new_url = f"{before_at}@[{host}]:{port}"
                
                return new_url
        
        elif node_url.startswith('vmess://'):
            # VMess 需要修改 JSON 配置
            vmess_data = node_url[8:].split('#')[0]
            label = node_url.split('#')[1] if '#' in node_url else ''
            
            decoded = decode_base64(vmess_data)
            if decoded:
                config = json.loads(decoded)
                config['add'] = host
                config['port'] = port
                
                new_json = json.dumps(config, ensure_ascii=False)
                new_encoded = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
                
                if label:
                    return f"vmess://{new_encoded}#{label}"
                else:
                    return f"vmess://{new_encoded}"
        
        else:
            # 对于 vless, trojan 等使用标准 URL 格式的协议
            # 确保 IPv6 地址被中括号包裹
            # 先移除可能存在的中括号
            node_url = node_url.replace(f"[{host}]", host)
            # 然后统一添加中括号
            node_url = node_url.replace(f"@{host}:{port}", f"@[{host}]:{port}")
            node_url = node_url.replace(f"//{host}:{port}", f"//[{host}]:{port}")
    
    except Exception as e:
        print(f"    ⚠ IPv6 格式化失败: {e}")
    
    return node_url

def check_node(node_url):
    """检查单个节点的连通性并更新标签"""
    host, port = parse_node_address(node_url)
    
    if not host or not port:
        return None, "无法解析地址"
    
    # 第一步：TCP ping 测试（1秒超时）
    is_alive = tcp_ping(host, port, timeout=1)
    
    if not is_alive:
        return None, f"✗ {host}:{port} - 连接超时"
    
    # 第二步：确定要查询的 IP
    query_ip = None
    original_host = host
    
    if is_domain(host):
        # 是域名，需要解析为 IP
        resolved_ip = resolve_domain_to_ip(host)
        if resolved_ip:
            query_ip = resolved_ip
        else:
            return None, f"✗ {host}:{port} - 域名解析失败"
    else:
        # 是 IP 地址（IPv4 或 IPv6）
        query_ip = host.strip('[]')
    
    # 第三步：查询 IP 信息
    ip_info = query_ip_info(query_ip)
    
    # 第四步：生成新标签
    new_label = generate_node_label(ip_info, query_ip)
    
    # 第五步：更新节点标签
    updated_node = update_node_label(node_url, new_label)
    
    # 第六步：标准化 IPv6 格式（只处理 IP 地址，不处理域名）
    if not is_domain(original_host):
        updated_node = normalize_ipv6_in_url(updated_node, original_host, port)
    
    status = f"✓ {original_host}:{port} -> {new_label}"
    
    return updated_node, status

def extract_nodes_from_file(file_path):
    """从文件中提取节点"""
    nodes = []
    
    try:
        file_name_lower = file_path.name.lower()
        if 'clash' in file_name_lower or file_path.suffix in ['.yaml', '.yml']:
            return nodes
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
        
        if not content:
            return nodes
        
        if is_base64(content):
            decoded = decode_base64(content)
            if decoded:
                lines = decoded.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and is_valid_node(line):
                        nodes.append(line)
                
                if nodes:
                    return nodes
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            if is_valid_node(line):
                nodes.append(line)
            
            elif is_base64(line) and len(line) > 20:
                decoded = decode_base64(line)
                if decoded:
                    decoded_lines = decoded.strip().split('\n')
                    for decoded_line in decoded_lines:
                        decoded_line = decoded_line.strip()
                        if decoded_line and is_valid_node(decoded_line):
                            nodes.append(decoded_line)
    
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")
    
    return nodes

def main():
    """主函数"""
    print("=" * 60)
    print("开始处理节点...")
    print("=" * 60)
    
    all_nodes = []
    source_path = Path('source_repo')
    
    if not source_path.exists():
        print("错误: source_repo 目录不存在")
        return
    
    exclude_dirs = {'.git', '.github', 'node_modules', '__pycache__'}
    
    file_count = 0
    processed_files = []
    
    # 遍历所有文件
    for file_path in source_path.rglob('*'):
        if file_path.is_dir():
            continue
        
        if any(excluded in file_path.parts for excluded in exclude_dirs):
            continue
        
        try:
            if file_path.stat().st_size > 10 * 1024 * 1024:
                continue
        except:
            continue
        
        file_count += 1
        print(f"\n[{file_count}] 处理: {file_path.relative_to(source_path)}")
        
        nodes = extract_nodes_from_file(file_path)
        if nodes:
            print(f"    ✓ 找到 {len(nodes)} 个节点")
            all_nodes.extend(nodes)
            processed_files.append((file_path.relative_to(source_path), len(nodes)))
        else:
            print(f"    - 未找到节点")
    
    print("\n" + "=" * 60)
    print("节点提取完成，开始连通性测试和标签更新...")
    print("=" * 60)
    
    # 去重
    unique_nodes = list(dict.fromkeys(all_nodes))
    
    print(f"\n📊 提取统计:")
    print(f"  - 扫描文件数: {file_count}")
    print(f"  - 有效文件数: {len(processed_files)}")
    print(f"  - 总节点数: {len(all_nodes)}")
    print(f"  - 去重后节点数: {len(unique_nodes)}")
    
    # TCP ping 测试和标签更新
    print(f"\n🔍 开始测试和更新标签 (TCP超时: 1秒)...")
    alive_nodes = []
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_node, node): node for node in unique_nodes}
        
        for i, future in enumerate(as_completed(futures), 1):
            updated_node, status = future.result()
            print(f"  [{i}/{len(unique_nodes)}] {status}")
            
            if updated_node:
                alive_nodes.append(updated_node)
    
    print("\n" + "=" * 60)
    print("处理完成")
    print("=" * 60)
    
    print(f"\n📊 最终统计:")
    print(f"  - 可用节点: {len(alive_nodes)} 个")
    print(f"  - 不可用节点: {len(unique_nodes) - len(alive_nodes)} 个")
    if len(unique_nodes) > 0:
        print(f"  - 可用率: {len(alive_nodes)/len(unique_nodes)*100:.1f}%")
    
    # 保存为 base64 编码的订阅文件
    if alive_nodes:
        merged_content = '\n'.join(alive_nodes)
        encoded_content = base64.b64encode(merged_content.encode('utf-8')).decode('utf-8')
        
        with open('merge-nodes.txt', 'w', encoding='utf-8') as f:
            f.write(encoded_content)
        
        print(f"\n✅ 已保存 {len(alive_nodes)} 个可用节点到 merge-nodes.txt")
        print(f"📝 文件大小: {len(encoded_content)} 字节")
    else:
        print("\n⚠️  没有可用的节点")

if __name__ == '__main__':
    main()
