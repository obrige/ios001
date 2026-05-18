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

def is_base64(s):
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
    try:
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        return decoded
    except Exception as e:
        return None

def is_valid_node(line):
    excluded_protocols = ['http://', 'https://', 'tcp://', 'udp://', 'ftp://', 'ftps://', 
                          'ws://', 'wss://', 'file://', 'data://', 'mailto:', 'tel:']
    
    line_lower = line.lower()
    if any(line_lower.startswith(proto) for proto in excluded_protocols):
        return False
    
    pattern = r'^[a-zA-Z0-9\-_]{2,10}://.+'
    return bool(re.match(pattern, line))

def is_ipv6(host):
    host = host.strip('[]')
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except:
        return False

def is_ipv4(host):
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except:
        return False

def is_domain(host):
    return not is_ipv4(host) and not is_ipv6(host)

def resolve_domain_to_ips_doh(host, retries=3):
    doh_servers = [
        'https://1.1.1.1/dns-query',
        'https://8.8.8.8/resolve',
        'https://dns.google/resolve'
    ]
    
    ipv4 = None
    ipv6 = None
    
    for qtype, qtype_name, qtype_num in [('AAAA', 'ipv6', 28), ('A', 'ipv4', 1)]:
        for attempt in range(retries):
            for doh_url in doh_servers:
                try:
                    if 'dns-query' in doh_url:
                        import struct
                        query_id = 0x1234
                        flags = 0x0100
                        questions = 1
                        answer_rrs = 0
                        authority_rrs = 0
                        additional_rrs = 0
                        
                        header = struct.pack('!HHHHHH', query_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
                        
                        qname = b''
                        for part in host.split('.'):
                            qname += bytes([len(part)]) + part.encode()
                        qname += b'\x00'
                        
                        qclass_in = 1
                        question = qname + struct.pack('!HH', qtype_num, qclass_in)
                        
                        dns_query = header + question
                        
                        req = urllib.request.Request(
                            doh_url,
                            data=dns_query,
                            headers={
                                'Content-Type': 'application/dns-message',
                                'Accept': 'application/dns-message'
                            }
                        )
                        
                        with urllib.request.urlopen(req, timeout=5) as response:
                            dns_response = response.read()
                            
                            offset = 12 + len(question)
                            
                            while offset < len(dns_response):
                                if dns_response[offset] & 0xC0 == 0xC0:
                                    offset += 2
                                else:
                                    while offset < len(dns_response) and dns_response[offset] != 0:
                                        offset += dns_response[offset] + 1
                                    offset += 1
                                
                                if offset + 10 > len(dns_response):
                                    break
                                
                                rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', dns_response[offset:offset+10])
                                offset += 10
                                
                                if rtype == 1 and rdlength == 4:
                                    ip = '.'.join(str(b) for b in dns_response[offset:offset+4])
                                    if qtype_name == 'ipv4':
                                        ipv4 = ip
                                    return ipv4, ipv6
                                elif rtype == 28 and rdlength == 16:
                                    ip_bytes = dns_response[offset:offset+16]
                                    ip = ':'.join(f'{ip_bytes[i]:02x}{ip_bytes[i+1]:02x}' for i in range(0, 16, 2))
                                    if qtype_name == 'ipv6':
                                        ipv6 = ip
                                    return ipv4, ipv6
                                
                                offset += rdlength
                    else:
                        url = f"{doh_url}?name={host}&type={qtype}"
                        req = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
                        
                        with urllib.request.urlopen(req, timeout=5) as response:
                            data = json.loads(response.read().decode('utf-8'))
                            
                            if 'Answer' in data:
                                for answer in data['Answer']:
                                    if answer.get('type') == qtype_num:
                                        ip = answer.get('data')
                                        if qtype_name == 'ipv4':
                                            ipv4 = ip
                                        else:
                                            ipv6 = ip
                                        break
                            
                            if (qtype_name == 'ipv4' and ipv4) or (qtype_name == 'ipv6' and ipv6):
                                break
                
                except Exception as e:
                    continue
                
                if (qtype_name == 'ipv4' and ipv4) or (qtype_name == 'ipv6' and ipv6):
                    break
            
            if (qtype_name == 'ipv4' and ipv4) or (qtype_name == 'ipv6' and ipv6):
                break
            
            if attempt < retries - 1:
                time.sleep(1)
    
    return ipv4, ipv6

def _normalize_ip_sb(data):
    """Normalize api.ip.sb response"""
    try:
        cc = data.get('country_code', '')
        if not cc:
            return None
        return {
            'country': {'code': cc, 'name': data.get('country', '')},
            'as': {'info': data.get('asn_organization', '') or data.get('isp', ''),
                   'name': f"AS{data['asn']}" if data.get('asn') else ''},
            'regions_short': [data['region']] if data.get('region') else [],
            'type': 'IPv4',
            'registered_country': {'code': cc}
        }
    except Exception:
        return None

def _normalize_ipinfo(data):
    """Normalize ipinfo.io response"""
    try:
        cc = data.get('country', '')
        if not cc:
            return None
        org = data.get('org', '')
        as_name, as_info = '', ''
        if org:
            parts = org.split(' ', 1)
            as_name = parts[0]
            as_info = parts[1] if len(parts) > 1 else ''
        return {
            'country': {'code': cc, 'name': ''},
            'as': {'info': as_info, 'name': as_name},
            'regions_short': [data['region']] if data.get('region') else [],
            'type': 'IPv4',
            'registered_country': {'code': cc}
        }
    except Exception:
        return None

def _normalize_ipwhois(data):
    """Normalize ipwho.is response"""
    try:
        if not data.get('success'):
            return None
        cc = data.get('country_code', '')
        if not cc:
            return None
        conn = data.get('connection', {})
        return {
            'country': {'code': cc, 'name': data.get('country', '')},
            'as': {'info': conn.get('org', '') or conn.get('isp', ''),
                   'name': f"AS{conn['asn']}" if conn.get('asn') else ''},
            'regions_short': [data['region']] if data.get('region') else [],
            'type': data.get('type', 'IPv4'),
            'registered_country': {'code': cc}
        }
    except Exception:
        return None

def _normalize_freeipapi(data):
    """Normalize freeipapi.com response"""
    try:
        cc = data.get('countryCode', '')
        if not cc:
            return None
        return {
            'country': {'code': cc, 'name': data.get('countryName', '')},
            'as': {'info': data.get('asnOrganization', ''),
                   'name': f"AS{data['asn']}" if data.get('asn') else ''},
            'regions_short': [data['regionName']] if data.get('regionName') else [],
            'type': 'IPv4',
            'registered_country': {'code': cc}
        }
    except Exception:
        return None

def _normalize_geodb(data):
    """Normalize geolocation-db.com response"""
    try:
        cc = data.get('country_code', '')
        if not cc:
            return None
        return {
            'country': {'code': cc, 'name': data.get('country_name', '')},
            'as': {'info': '', 'name': ''},
            'regions_short': [data['state']] if data.get('state') else [],
            'type': 'IPv4',
            'registered_country': {'code': cc}
        }
    except Exception:
        return None

def query_ip_info(ip, retries=2):
    if not ip:
        return None

    ip = ip.strip('[]')

    api_sources = [
        ('https://api.ip.sb/geoip/{}',          _normalize_ip_sb),
        ('https://ipinfo.io/{}/json',            _normalize_ipinfo),
        ('https://ipwho.is/{}',                  _normalize_ipwhois),
        ('https://freeipapi.com/api/json/{}',    _normalize_freeipapi),
        ('https://geolocation-db.com/json/{}',   _normalize_geodb),
    ]

    for url_tpl, normalizer in api_sources:
        for attempt in range(retries):
            try:
                url = url_tpl.format(ip)
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode('utf-8'))
                    result = normalizer(data)
                    if result:
                        return result
            except Exception:
                if attempt < retries - 1:
                    time.sleep(1)

    print(f"    ⚠ IP查询失败: {ip} - 所有API均不可用")
    return None

def get_country_emoji(country_code):
    if not country_code or len(country_code) != 2:
        return '🌐'
    
    country_code = country_code.upper()
    
    try:
        flag = ''.join(chr(0x1F1E6 - ord('A') + ord(char)) for char in country_code)
        return flag
    except:
        return '🌐'

def generate_node_label(ipv4_info, ipv6_info, is_broadcast):
    ip_info = ipv6_info if ipv6_info else ipv4_info
    
    if not ip_info:
        return f"🌐|Unknown"
    
    parts = []
    
    country_code = ip_info.get('country', {}).get('code', '')
    country_name = ip_info.get('country', {}).get('name', '')
    
    if country_code:
        emoji = get_country_emoji(country_code)
        parts.append(emoji)
    
    if country_name:
        parts.append(country_name)
    
    as_info = ip_info.get('as', {}).get('info', '') or ip_info.get('as', {}).get('name', '')
    if as_info:
        parts.append(as_info)
    
    regions_short = ip_info.get('regions_short', [])
    if regions_short:
        parts.append('-'.join(regions_short))
    
    ip_type = ip_info.get('type', '')
    if ip_type:
        parts.append(ip_type)
    
    if is_broadcast:
        parts.append('广播IP')
    else:
        parts.append('原生IP')
    
    label = '|'.join(parts) if parts else f"🌐|Unknown"
    return label

def parse_node_address(node_url):
    try:
        if node_url.startswith('ss://') or node_url.startswith('shadowsocks://'):
            parts = node_url.split('://')[1].split('#')[0].split('@')
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
        
        else:
            parsed = urllib.parse.urlparse(node_url)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return host, port
                
    except Exception as e:
        pass
    
    return None, None

def tcp_ping(host, port, timeout=1):
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
    if '#' in node_url:
        node_url = node_url.split('#')[0]
    
    encoded_label = urllib.parse.quote(new_label)
    return f"{node_url}#{encoded_label}"

def normalize_ipv6_in_url(node_url, host, port):
    if not is_ipv6(host):
        return node_url
    
    try:
        if node_url.startswith('ss://') or node_url.startswith('shadowsocks://'):
            parts = node_url.split('@')
            if len(parts) == 2:
                before_at = parts[0]
                after_at = parts[1]
                
                if '#' in after_at:
                    server_part, label_part = after_at.split('#', 1)
                    new_url = f"{before_at}@[{host}]:{port}#{label_part}"
                else:
                    new_url = f"{before_at}@[{host}]:{port}"
                
                return new_url
        
        elif node_url.startswith('vmess://'):
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
            node_url = node_url.replace(f"[{host}]", host)
            node_url = node_url.replace(f"@{host}:{port}", f"@[{host}]:{port}")
            node_url = node_url.replace(f"//{host}:{port}", f"//[{host}]:{port}")
    
    except Exception as e:
        print(f"    ⚠ IPv6 格式化失败: {e}")
    
    return node_url

def check_node(node_url):
    host, port = parse_node_address(node_url)
    
    if not host or not port:
        return None, "无法解析地址"
    
    is_alive = tcp_ping(host, port, timeout=1)
    
    if not is_alive:
        return None, f"✗ {host}:{port} - 连接超时"
    
    original_host = host
    ipv4 = None
    ipv6 = None
    
    if is_domain(host):
        ipv4, ipv6 = resolve_domain_to_ips_doh(host)
        if not ipv4 and not ipv6:
            return None, f"✗ {host}:{port} - 域名解析失败"
    else:
        if is_ipv4(host):
            ipv4 = host
        elif is_ipv6(host):
            ipv6 = host.strip('[]')
    
    ipv4_info = None
    ipv6_info = None
    
    if ipv6:
        ipv6_info = query_ip_info(ipv6)
    
    if ipv4:
        ipv4_info = query_ip_info(ipv4)
    
    is_broadcast = False
    
    if ipv4_info and ipv6_info:
        ipv4_country = ipv4_info.get('country', {}).get('code', '')
        ipv6_country = ipv6_info.get('country', {}).get('code', '')
        
        if ipv4_country != ipv6_country:
            is_broadcast = True
    
    if not is_broadcast:
        check_info = ipv6_info if ipv6_info else ipv4_info
        if check_info:
            registered_country = check_info.get('registered_country', {}).get('code', '')
            country_code = check_info.get('country', {}).get('code', '')
            
            if registered_country and country_code and registered_country != country_code:
                is_broadcast = True
    
    new_label = generate_node_label(ipv4_info, ipv6_info, is_broadcast)
    
    updated_node = update_node_label(node_url, new_label)
    
    if not is_domain(original_host):
        updated_node = normalize_ipv6_in_url(updated_node, original_host, port)
    
    query_ip_display = ipv6 if ipv6 else ipv4
    status = f"✓ {original_host}:{port} -> {new_label}"
    
    return updated_node, status

def extract_nodes_from_file(file_path):
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
    
    unique_nodes = list(dict.fromkeys(all_nodes))
    
    print(f"\n📊 提取统计:")
    print(f"  - 扫描文件数: {file_count}")
    print(f"  - 有效文件数: {len(processed_files)}")
    print(f"  - 总节点数: {len(all_nodes)}")
    print(f"  - 去重后节点数: {len(unique_nodes)}")
    
    print(f"\n🔍 开始测试和更新标签 (TCP超时: 1秒)...")
    alive_nodes = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
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
