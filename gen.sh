#!/bin/bash

# 一键生成代理节点链接脚本
# 支持 VLESS+Reality+Vision、Shadowsocks、Hysteria2 等协议

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置文件路径
CONFIG_DIR="$HOME/.proxy_nodes"
NODES_FILE="$CONFIG_DIR/nodes.txt"

# 默认SNI
DEFAULT_SNI="itunes.apple.com"

# 初始化配置目录
init_config() {
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
    fi
    if [ ! -f "$NODES_FILE" ]; then
        touch "$NODES_FILE"
    fi
}

# 生成随机UUID
generate_uuid() {
    cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "$(date +%s)-$(shuf -i 1000-9999 -n 1)-$(shuf -i 1000-9999 -n 1)-$(shuf -i 1000-9999 -n 1)-$(shuf -i 100000000000-999999999999 -n 1)"
}

# 生成随机密码
generate_password() {
    local length=${1:-16}
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length"
}

# 生成随机端口
generate_port() {
    shuf -i 10000-65535 -n 1
}

# Base64编码
base64_encode() {
    echo -n "$1" | base64 | tr -d '\n'
}

# 获取服务器IPv4地址
get_server_ipv4() {
    local ip
    ip=$(curl -s4 --connect-timeout 5 ip.sb 2>/dev/null || curl -s4 --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s4 --connect-timeout 5 icanhazip.com 2>/dev/null)
    echo "$ip"
}

# 获取服务器IPv6地址
get_server_ipv6() {
    local ip
    ip=$(curl -s6 --connect-timeout 5 ip.sb 2>/dev/null || curl -s6 --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s6 --connect-timeout 5 icanhazip.com 2>/dev/null)
    echo "$ip"
}

# 获取服务器IP（交互式，用于手动输入）
get_server_ips() {
    echo -e "${YELLOW}正在检测服务器IP地址...${NC}"
    
    SERVER_IPV4=$(get_server_ipv4)
    SERVER_IPV6=$(get_server_ipv6)
    
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${GREEN}检测到 IPv4: $SERVER_IPV4${NC}"
    else
        echo -e "${YELLOW}未检测到 IPv4 地址${NC}"
    fi
    
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${GREEN}检测到 IPv6: $SERVER_IPV6${NC}"
    else
        echo -e "${YELLOW}未检测到 IPv6 地址${NC}"
    fi
    
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}无法自动获取IP地址${NC}"
        read -p "请手动输入 IPv4 地址 (留空跳过): " SERVER_IPV4
        read -p "请手动输入 IPv6 地址 (留空跳过): " SERVER_IPV6
    else
        read -p "是否修改 IPv4 地址? [留空使用检测值]: " input_ipv4
        [ -n "$input_ipv4" ] && SERVER_IPV4="$input_ipv4"
        read -p "是否修改 IPv6 地址? [留空使用检测值]: " input_ipv6
        [ -n "$input_ipv6" ] && SERVER_IPV6="$input_ipv6"
    fi
    
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}错误：至少需要一个IP地址！${NC}"
        return 1
    fi
    
    echo ""
    return 0
}

# 保存节点到文件
save_node() {
    local protocol=$1
    local link=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$protocol] $link" >> "$NODES_FILE"
    echo -e "${GREEN}节点已保存！${NC}"
}

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}       一键代理节点生成工具 v1.0       ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} 新建节点"
    echo -e "${GREEN}2.${NC} 查看已存在的节点"
    echo -e "${GREEN}3.${NC} 删除所有节点记录"
    echo -e "${GREEN}0.${NC} 退出"
    echo ""
    echo -e "${CYAN}========================================${NC}"
    read -p "请选择操作 [0-3]: " main_choice
}

# 显示协议菜单
show_protocol_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}          选择节点协议类型             ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} VLESS + Reality + Vision"
    echo -e "${GREEN}2.${NC} Shadowsocks (SS)"
    echo -e "${GREEN}3.${NC} Hysteria2 (HY2)"
    echo -e "${GREEN}4.${NC} VMESS + WS"
    echo -e "${GREEN}5.${NC} Trojan"
    echo -e "${GREEN}6.${NC} VLESS + WS"
    echo -e "${GREEN}0.${NC} 返回主菜单"
    echo ""
    echo -e "${CYAN}========================================${NC}"
    read -p "请选择协议 [0-6]: " protocol_choice
}

# 生成 VLESS + Reality + Vision 节点
generate_vless_reality() {
    echo -e "${YELLOW}正在生成 VLESS + Reality + Vision 节点...${NC}"
    echo ""
    
    # 获取参数
    get_server_ips || return
    
    read -p "端口 [默认: 443]: " port
    port=${port:-443}
    
    local uuid=$(generate_uuid)
    read -p "UUID [默认: $uuid]: " input_uuid
    uuid=${input_uuid:-$uuid}
    
    read -p "SNI [默认: $DEFAULT_SNI]: " sni
    sni=${sni:-$DEFAULT_SNI}
    
    # Reality 密钥对 - 尝试使用 xray 生成，否则需要用户输入
    local public_key=""
    local private_key=""
    
    if command -v xray &> /dev/null; then
        echo -e "${GREEN}检测到 xray，正在生成 Reality 密钥对...${NC}"
        local keys=$(xray x25519)
        private_key=$(echo "$keys" | grep "Private key:" | awk '{print $3}')
        public_key=$(echo "$keys" | grep "Public key:" | awk '{print $3}')
        echo -e "${GREEN}已自动生成密钥对${NC}"
    fi
    
    if [ -z "$public_key" ]; then
        echo -e "${YELLOW}========================================${NC}"
        echo -e "${YELLOW}需要 Reality 密钥对！${NC}"
        echo -e "${YELLOW}请在服务器上运行: xray x25519${NC}"
        echo -e "${YELLOW}或使用在线工具生成 X25519 密钥对${NC}"
        echo -e "${YELLOW}========================================${NC}"
    fi
    
    read -p "Reality Private Key (服务端用) [留空使用自动生成]: " input_privkey
    [ -n "$input_privkey" ] && private_key="$input_privkey"
    
    read -p "Reality Public Key (客户端用) [留空使用自动生成]: " input_pubkey
    [ -n "$input_pubkey" ] && public_key="$input_pubkey"
    
    if [ -z "$public_key" ]; then
        echo -e "${RED}错误：必须提供 Reality Public Key！${NC}"
        echo -e "${YELLOW}请先运行 'xray x25519' 生成密钥对${NC}"
        return 1
    fi
    
    local short_id=$(openssl rand -hex 8 2>/dev/null || head -c 16 /dev/urandom | xxd -p | head -c 16)
    read -p "Short ID [默认: $short_id]: " input_shortid
    short_id=${input_shortid:-$short_id}
    
    read -p "节点名称 [默认: VLESS-Reality]: " node_name
    node_name=${node_name:-"VLESS-Reality"}
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}VLESS + Reality + Vision 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 生成 IPv4 节点
    echo -e "${CYAN}【IPv4 节点链接】${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        local node_name_v4="${node_name}-IPv4"
        local node_name_v4_encoded=$(echo -n "$node_name_v4" | sed 's/ /%20/g')
        local link_v4="vless://${uuid}@${SERVER_IPV4}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#${node_name_v4_encoded}"
        echo -e "${YELLOW}$link_v4${NC}"
    else
        echo -e "${RED}无（未检测到 IPv4 地址）${NC}"
    fi
    echo ""
    
    # 生成 IPv6 节点
    echo -e "${CYAN}【IPv6 节点链接】${NC}"
    if [ -n "$SERVER_IPV6" ]; then
        local node_name_v6="${node_name}-IPv6"
        local node_name_v6_encoded=$(echo -n "$node_name_v6" | sed 's/ /%20/g')
        local link_v6="vless://${uuid}@[${SERVER_IPV6}]:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#${node_name_v6_encoded}"
        echo -e "${YELLOW}$link_v6${NC}"
    else
        echo -e "${RED}无（未检测到 IPv6 地址）${NC}"
    fi
    echo ""
    
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  IPv4: ${SERVER_IPV4:-无}"
    echo -e "  IPv6: ${SERVER_IPV6:-无}"
    echo -e "  端口: $port"
    echo -e "  UUID: $uuid"
    echo -e "  SNI: $sni"
    echo -e "  Public Key: $public_key"
    echo -e "  Private Key: ${private_key:-未提供}"
    echo -e "  Short ID: $short_id"
    echo ""
    
    # 输出服务端配置提示
    echo -e "${BLUE}==================== 服务端配置 (Xray) ====================${NC}"
    cat <<EOF
{
  "inbounds": [{
    "port": ${port},
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "${uuid}", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "${sni}:443",
        "serverNames": ["${sni}"],
        "privateKey": "${private_key:-你的私钥}",
        "shortIds": ["${short_id}"]
      }
    }
  }]
}
EOF
    echo -e "${BLUE}============================================================${NC}"
    echo ""
    
    # 生成 Clash 配置
    echo -e "${PURPLE}==================== Clash 配置 ====================${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${CYAN}# IPv4 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv4"
  type: vless
  server: ${SERVER_IPV4}
  port: ${port}
  uuid: ${uuid}
  network: tcp
  tls: true
  udp: true
  flow: xtls-rprx-vision
  servername: ${sni}
  client-fingerprint: chrome
  reality-opts:
    public-key: ${public_key}
    short-id: ${short_id}
EOF
        echo ""
    fi
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${CYAN}# IPv6 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv6"
  type: vless
  server: ${SERVER_IPV6}
  port: ${port}
  uuid: ${uuid}
  network: tcp
  tls: true
  udp: true
  flow: xtls-rprx-vision
  servername: ${sni}
  client-fingerprint: chrome
  reality-opts:
    public-key: ${public_key}
    short-id: ${short_id}
EOF
        echo ""
    fi
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}无可用的 Clash 配置${NC}"
    fi
    echo -e "${PURPLE}====================================================${NC}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        [ -n "$SERVER_IPV4" ] && save_node "VLESS-Reality-IPv4" "$link_v4"
        [ -n "$SERVER_IPV6" ] && save_node "VLESS-Reality-IPv6" "$link_v6"
    fi
}

# 生成 Shadowsocks 节点
generate_shadowsocks() {
    echo -e "${YELLOW}正在生成 Shadowsocks 节点...${NC}"
    echo ""
    
    get_server_ips || return
    
    read -p "端口 [默认随机]: " port
    port=${port:-$(generate_port)}
    
    local password=$(generate_password 16)
    read -p "密码 [默认随机]: " input_password
    password=${input_password:-$password}
    
    echo "加密方式选择:"
    echo "  1. aes-256-gcm"
    echo "  2. aes-128-gcm"
    echo "  3. chacha20-ietf-poly1305"
    echo "  4. 2022-blake3-aes-256-gcm"
    echo "  5. 2022-blake3-chacha20-poly1305"
    read -p "选择加密方式 [默认1]: " method_choice
    
    case $method_choice in
        2) method="aes-128-gcm" ;;
        3) method="chacha20-ietf-poly1305" ;;
        4) method="2022-blake3-aes-256-gcm" ;;
        5) method="2022-blake3-chacha20-poly1305" ;;
        *) method="aes-256-gcm" ;;
    esac
    
    read -p "节点名称 [默认: SS-Node]: " node_name
    node_name=${node_name:-"SS-Node"}
    
    # SS链接格式: ss://BASE64(method:password)@server:port#name
    local userinfo=$(base64_encode "${method}:${password}")
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Shadowsocks 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 生成 IPv4 节点
    echo -e "${CYAN}【IPv4 节点链接】${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        local node_name_v4="${node_name}-IPv4"
        local node_name_v4_encoded=$(echo -n "$node_name_v4" | sed 's/ /%20/g')
        local link_v4="ss://${userinfo}@${SERVER_IPV4}:${port}#${node_name_v4_encoded}"
        echo -e "${YELLOW}$link_v4${NC}"
    else
        echo -e "${RED}无（未检测到 IPv4 地址）${NC}"
    fi
    echo ""
    
    # 生成 IPv6 节点
    echo -e "${CYAN}【IPv6 节点链接】${NC}"
    if [ -n "$SERVER_IPV6" ]; then
        local node_name_v6="${node_name}-IPv6"
        local node_name_v6_encoded=$(echo -n "$node_name_v6" | sed 's/ /%20/g')
        local link_v6="ss://${userinfo}@[${SERVER_IPV6}]:${port}#${node_name_v6_encoded}"
        echo -e "${YELLOW}$link_v6${NC}"
    else
        echo -e "${RED}无（未检测到 IPv6 地址）${NC}"
    fi
    echo ""
    
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  IPv4: ${SERVER_IPV4:-无}"
    echo -e "  IPv6: ${SERVER_IPV6:-无}"
    echo -e "  端口: $port"
    echo -e "  密码: $password"
    echo -e "  加密方式: $method"
    echo ""
    
    # 生成 Clash 配置
    echo -e "${PURPLE}==================== Clash 配置 ====================${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${CYAN}# IPv4 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv4"
  type: ss
  server: ${SERVER_IPV4}
  port: ${port}
  cipher: ${method}
  password: "${password}"
  udp: true
EOF
        echo ""
    fi
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${CYAN}# IPv6 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv6"
  type: ss
  server: ${SERVER_IPV6}
  port: ${port}
  cipher: ${method}
  password: "${password}"
  udp: true
EOF
        echo ""
    fi
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}无可用的 Clash 配置${NC}"
    fi
    echo -e "${PURPLE}====================================================${NC}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        [ -n "$SERVER_IPV4" ] && save_node "Shadowsocks-IPv4" "$link_v4"
        [ -n "$SERVER_IPV6" ] && save_node "Shadowsocks-IPv6" "$link_v6"
    fi
}

# 生成 Hysteria2 节点
generate_hysteria2() {
    echo -e "${YELLOW}正在生成 Hysteria2 节点...${NC}"
    echo ""
    
    get_server_ips || return
    
    read -p "端口 [默认: 443]: " port
    port=${port:-443}
    
    local password=$(generate_password 32)
    read -p "密码/Auth [默认随机]: " input_password
    password=${input_password:-$password}
    
    read -p "SNI/域名 [默认: $DEFAULT_SNI]: " sni
    sni=${sni:-$DEFAULT_SNI}
    
    echo -e "${YELLOW}注意：Hysteria2 需要有效的 TLS 证书！${NC}"
    echo -e "${YELLOW}如果使用自签证书，客户端需要跳过证书验证${NC}"
    read -p "跳过证书验证 [Y/n]: " insecure
    if [[ "$insecure" =~ ^[Nn]$ ]]; then
        insecure_param=""
        skip_cert="false"
    else
        insecure_param="&insecure=1"
        skip_cert="true"
    fi
    
    read -p "节点名称 [默认: HY2-Node]: " node_name
    node_name=${node_name:-"HY2-Node"}
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Hysteria2 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 生成 IPv4 节点
    echo -e "${CYAN}【IPv4 节点链接】${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        local node_name_v4="${node_name}-IPv4"
        local node_name_v4_encoded=$(echo -n "$node_name_v4" | sed 's/ /%20/g')
        local link_v4="hysteria2://${password}@${SERVER_IPV4}:${port}?sni=${sni}${insecure_param}#${node_name_v4_encoded}"
        echo -e "${YELLOW}$link_v4${NC}"
    else
        echo -e "${RED}无（未检测到 IPv4 地址）${NC}"
    fi
    echo ""
    
    # 生成 IPv6 节点
    echo -e "${CYAN}【IPv6 节点链接】${NC}"
    if [ -n "$SERVER_IPV6" ]; then
        local node_name_v6="${node_name}-IPv6"
        local node_name_v6_encoded=$(echo -n "$node_name_v6" | sed 's/ /%20/g')
        local link_v6="hysteria2://${password}@[${SERVER_IPV6}]:${port}?sni=${sni}${insecure_param}#${node_name_v6_encoded}"
        echo -e "${YELLOW}$link_v6${NC}"
    else
        echo -e "${RED}无（未检测到 IPv6 地址）${NC}"
    fi
    echo ""
    
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  IPv4: ${SERVER_IPV4:-无}"
    echo -e "  IPv6: ${SERVER_IPV6:-无}"
    echo -e "  端口: $port"
    echo -e "  密码: $password"
    echo -e "  SNI: $sni"
    echo -e "  跳过验证: $skip_cert"
    echo ""
    
    # 输出服务端配置提示
    echo -e "${BLUE}==================== 服务端配置 (Hysteria2) ====================${NC}"
    cat <<EOF
listen: :${port}
tls:
  cert: /path/to/cert.pem  # 修改为你的证书路径
  key: /path/to/key.pem    # 修改为你的私钥路径
auth:
  type: password
  password: ${password}
masquerade:
  type: proxy
  proxy:
    url: https://${sni}
    rewriteHost: true
EOF
    echo -e "${BLUE}=================================================================${NC}"
    echo ""
    
    # 生成 Clash 配置 (Clash Meta/Mihomo 支持)
    echo -e "${PURPLE}==================== Clash 配置 (Mihomo) ====================${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${CYAN}# IPv4 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv4"
  type: hysteria2
  server: ${SERVER_IPV4}
  port: ${port}
  password: ${password}
  sni: ${sni}
  skip-cert-verify: ${skip_cert}
EOF
        echo ""
    fi
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${CYAN}# IPv6 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv6"
  type: hysteria2
  server: ${SERVER_IPV6}
  port: ${port}
  password: ${password}
  sni: ${sni}
  skip-cert-verify: ${skip_cert}
EOF
        echo ""
    fi
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}无可用的 Clash 配置${NC}"
    fi
    echo -e "${PURPLE}=============================================================${NC}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        [ -n "$SERVER_IPV4" ] && save_node "Hysteria2-IPv4" "$link_v4"
        [ -n "$SERVER_IPV6" ] && save_node "Hysteria2-IPv6" "$link_v6"
    fi
}

# 生成 VMESS + WS 节点
generate_vmess_ws() {
    echo -e "${YELLOW}正在生成 VMESS + WS 节点...${NC}"
    echo ""
    
    get_server_ips || return
    
    read -p "端口 [默认随机]: " port
    port=${port:-$(generate_port)}
    
    local uuid=$(generate_uuid)
    read -p "UUID [默认: $uuid]: " input_uuid
    uuid=${input_uuid:-$uuid}
    
    read -p "WebSocket 路径 [默认: /ws]: " ws_path
    ws_path=${ws_path:-"/ws"}
    
    read -p "Host [默认: $DEFAULT_SNI]: " host
    host=${host:-$DEFAULT_SNI}
    
    read -p "是否启用TLS? [y/N]: " use_tls
    if [[ "$use_tls" =~ ^[Yy]$ ]]; then
        tls="tls"
    else
        tls=""
    fi
    
    read -p "节点名称 [默认: VMESS-WS]: " node_name
    node_name=${node_name:-"VMESS-WS"}
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}VMESS + WS 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 生成 IPv4 节点
    echo -e "${CYAN}【IPv4 节点链接】${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        local node_name_v4="${node_name}-IPv4"
        local vmess_json_v4=$(cat <<EOF
{
  "v": "2",
  "ps": "${node_name_v4}",
  "add": "${SERVER_IPV4}",
  "port": "${port}",
  "id": "${uuid}",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "${host}",
  "path": "${ws_path}",
  "tls": "${tls}",
  "sni": "${host}",
  "alpn": ""
}
EOF
)
        local vmess_base64_v4=$(echo -n "$vmess_json_v4" | base64 | tr -d '\n')
        local link_v4="vmess://${vmess_base64_v4}"
        echo -e "${YELLOW}$link_v4${NC}"
    else
        echo -e "${RED}无（未检测到 IPv4 地址）${NC}"
    fi
    echo ""
    
    # 生成 IPv6 节点
    echo -e "${CYAN}【IPv6 节点链接】${NC}"
    if [ -n "$SERVER_IPV6" ]; then
        local node_name_v6="${node_name}-IPv6"
        local vmess_json_v6=$(cat <<EOF
{
  "v": "2",
  "ps": "${node_name_v6}",
  "add": "${SERVER_IPV6}",
  "port": "${port}",
  "id": "${uuid}",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "${host}",
  "path": "${ws_path}",
  "tls": "${tls}",
  "sni": "${host}",
  "alpn": ""
}
EOF
)
        local vmess_base64_v6=$(echo -n "$vmess_json_v6" | base64 | tr -d '\n')
        local link_v6="vmess://${vmess_base64_v6}"
        echo -e "${YELLOW}$link_v6${NC}"
    else
        echo -e "${RED}无（未检测到 IPv6 地址）${NC}"
    fi
    echo ""
    
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  IPv4: ${SERVER_IPV4:-无}"
    echo -e "  IPv6: ${SERVER_IPV6:-无}"
    echo -e "  端口: $port"
    echo -e "  UUID: $uuid"
    echo -e "  WS路径: $ws_path"
    echo -e "  Host: $host"
    echo -e "  TLS: ${tls:-无}"
    echo ""
    
    # 生成 Clash 配置
    local tls_enabled="false"
    [[ "$tls" == "tls" ]] && tls_enabled="true"
    echo -e "${PURPLE}==================== Clash 配置 ====================${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${CYAN}# IPv4 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv4"
  type: vmess
  server: ${SERVER_IPV4}
  port: ${port}
  uuid: ${uuid}
  alterId: 0
  cipher: auto
  udp: true
  tls: ${tls_enabled}
  servername: ${host}
  network: ws
  ws-opts:
    path: ${ws_path}
    headers:
      Host: ${host}
EOF
        echo ""
    fi
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${CYAN}# IPv6 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv6"
  type: vmess
  server: ${SERVER_IPV6}
  port: ${port}
  uuid: ${uuid}
  alterId: 0
  cipher: auto
  udp: true
  tls: ${tls_enabled}
  servername: ${host}
  network: ws
  ws-opts:
    path: ${ws_path}
    headers:
      Host: ${host}
EOF
        echo ""
    fi
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}无可用的 Clash 配置${NC}"
    fi
    echo -e "${PURPLE}====================================================${NC}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        [ -n "$SERVER_IPV4" ] && save_node "VMESS-WS-IPv4" "$link_v4"
        [ -n "$SERVER_IPV6" ] && save_node "VMESS-WS-IPv6" "$link_v6"
    fi
}

# 生成 Trojan 节点
generate_trojan() {
    echo -e "${YELLOW}正在生成 Trojan 节点...${NC}"
    echo ""
    
    get_server_ips || return
    
    read -p "端口 [默认: 443]: " port
    port=${port:-443}
    
    local password=$(generate_password 32)
    read -p "密码 [默认随机]: " input_password
    password=${input_password:-$password}
    
    read -p "SNI [默认: $DEFAULT_SNI]: " sni
    sni=${sni:-$DEFAULT_SNI}
    
    read -p "跳过证书验证 [Y/n]: " allow_insecure
    if [[ "$allow_insecure" =~ ^[Nn]$ ]]; then
        insecure_param=""
    else
        insecure_param="&allowInsecure=1"
    fi
    
    read -p "节点名称 [默认: Trojan-Node]: " node_name
    node_name=${node_name:-"Trojan-Node"}
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Trojan 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 生成 IPv4 节点
    echo -e "${CYAN}【IPv4 节点链接】${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        local node_name_v4="${node_name}-IPv4"
        local node_name_v4_encoded=$(echo -n "$node_name_v4" | sed 's/ /%20/g')
        local link_v4="trojan://${password}@${SERVER_IPV4}:${port}?security=tls&sni=${sni}&type=tcp${insecure_param}#${node_name_v4_encoded}"
        echo -e "${YELLOW}$link_v4${NC}"
    else
        echo -e "${RED}无（未检测到 IPv4 地址）${NC}"
    fi
    echo ""
    
    # 生成 IPv6 节点
    echo -e "${CYAN}【IPv6 节点链接】${NC}"
    if [ -n "$SERVER_IPV6" ]; then
        local node_name_v6="${node_name}-IPv6"
        local node_name_v6_encoded=$(echo -n "$node_name_v6" | sed 's/ /%20/g')
        local link_v6="trojan://${password}@[${SERVER_IPV6}]:${port}?security=tls&sni=${sni}&type=tcp${insecure_param}#${node_name_v6_encoded}"
        echo -e "${YELLOW}$link_v6${NC}"
    else
        echo -e "${RED}无（未检测到 IPv6 地址）${NC}"
    fi
    echo ""
    
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  IPv4: ${SERVER_IPV4:-无}"
    echo -e "  IPv6: ${SERVER_IPV6:-无}"
    echo -e "  端口: $port"
    echo -e "  密码: $password"
    echo -e "  SNI: $sni"
    echo ""
    
    # 生成 Clash 配置
    local skip_cert="false"
    [[ -n "$insecure_param" ]] && skip_cert="true"
    echo -e "${PURPLE}==================== Clash 配置 ====================${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${CYAN}# IPv4 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv4"
  type: trojan
  server: ${SERVER_IPV4}
  port: ${port}
  password: ${password}
  udp: true
  sni: ${sni}
  skip-cert-verify: ${skip_cert}
EOF
        echo ""
    fi
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${CYAN}# IPv6 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv6"
  type: trojan
  server: ${SERVER_IPV6}
  port: ${port}
  password: ${password}
  udp: true
  sni: ${sni}
  skip-cert-verify: ${skip_cert}
EOF
        echo ""
    fi
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}无可用的 Clash 配置${NC}"
    fi
    echo -e "${PURPLE}====================================================${NC}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        [ -n "$SERVER_IPV4" ] && save_node "Trojan-IPv4" "$link_v4"
        [ -n "$SERVER_IPV6" ] && save_node "Trojan-IPv6" "$link_v6"
    fi
}

# 生成 VLESS + WS 节点
generate_vless_ws() {
    echo -e "${YELLOW}正在生成 VLESS + WS 节点...${NC}"
    echo ""
    
    get_server_ips || return
    
    read -p "端口 [默认随机]: " port
    port=${port:-$(generate_port)}
    
    local uuid=$(generate_uuid)
    read -p "UUID [默认: $uuid]: " input_uuid
    uuid=${input_uuid:-$uuid}
    
    read -p "WebSocket 路径 [默认: /ws]: " ws_path
    ws_path=${ws_path:-"/ws"}
    
    read -p "Host [默认: $DEFAULT_SNI]: " host
    host=${host:-$DEFAULT_SNI}
    
    read -p "是否启用TLS? [y/N]: " use_tls
    if [[ "$use_tls" =~ ^[Yy]$ ]]; then
        security="tls"
        tls_param="&security=tls&sni=${host}"
    else
        security="none"
        tls_param="&security=none"
    fi
    
    read -p "节点名称 [默认: VLESS-WS]: " node_name
    node_name=${node_name:-"VLESS-WS"}
    
    local ws_path_encoded=$(echo -n "$ws_path" | sed 's/\//%2F/g')
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}VLESS + WS 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # 生成 IPv4 节点
    echo -e "${CYAN}【IPv4 节点链接】${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        local node_name_v4="${node_name}-IPv4"
        local node_name_v4_encoded=$(echo -n "$node_name_v4" | sed 's/ /%20/g')
        local link_v4="vless://${uuid}@${SERVER_IPV4}:${port}?encryption=none&type=ws&host=${host}&path=${ws_path_encoded}${tls_param}#${node_name_v4_encoded}"
        echo -e "${YELLOW}$link_v4${NC}"
    else
        echo -e "${RED}无（未检测到 IPv4 地址）${NC}"
    fi
    echo ""
    
    # 生成 IPv6 节点
    echo -e "${CYAN}【IPv6 节点链接】${NC}"
    if [ -n "$SERVER_IPV6" ]; then
        local node_name_v6="${node_name}-IPv6"
        local node_name_v6_encoded=$(echo -n "$node_name_v6" | sed 's/ /%20/g')
        local link_v6="vless://${uuid}@[${SERVER_IPV6}]:${port}?encryption=none&type=ws&host=${host}&path=${ws_path_encoded}${tls_param}#${node_name_v6_encoded}"
        echo -e "${YELLOW}$link_v6${NC}"
    else
        echo -e "${RED}无（未检测到 IPv6 地址）${NC}"
    fi
    echo ""
    
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  IPv4: ${SERVER_IPV4:-无}"
    echo -e "  IPv6: ${SERVER_IPV6:-无}"
    echo -e "  端口: $port"
    echo -e "  UUID: $uuid"
    echo -e "  WS路径: $ws_path"
    echo -e "  Host: $host"
    echo -e "  TLS: ${security}"
    echo ""
    
    # 生成 Clash 配置 (Clash Meta/Mihomo 支持 VLESS)
    local tls_enabled="false"
    [[ "$security" == "tls" ]] && tls_enabled="true"
    echo -e "${PURPLE}==================== Clash 配置 (Mihomo) ====================${NC}"
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${CYAN}# IPv4 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv4"
  type: vless
  server: ${SERVER_IPV4}
  port: ${port}
  uuid: ${uuid}
  udp: true
  tls: ${tls_enabled}
  servername: ${host}
  network: ws
  ws-opts:
    path: ${ws_path}
    headers:
      Host: ${host}
EOF
        echo ""
    fi
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${CYAN}# IPv6 节点${NC}"
        cat <<EOF
- name: "${node_name}-IPv6"
  type: vless
  server: ${SERVER_IPV6}
  port: ${port}
  uuid: ${uuid}
  udp: true
  tls: ${tls_enabled}
  servername: ${host}
  network: ws
  ws-opts:
    path: ${ws_path}
    headers:
      Host: ${host}
EOF
        echo ""
    fi
    if [ -z "$SERVER_IPV4" ] && [ -z "$SERVER_IPV6" ]; then
        echo -e "${RED}无可用的 Clash 配置${NC}"
    fi
    echo -e "${PURPLE}=============================================================${NC}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        [ -n "$SERVER_IPV4" ] && save_node "VLESS-WS-IPv4" "$link_v4"
        [ -n "$SERVER_IPV6" ] && save_node "VLESS-WS-IPv6" "$link_v6"
    fi
}

# 查看已存在的节点
view_nodes() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}           已保存的节点列表            ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    
    if [ ! -s "$NODES_FILE" ]; then
        echo -e "${YELLOW}暂无保存的节点${NC}"
    else
        local count=1
        while IFS= read -r line; do
            echo -e "${GREEN}[$count]${NC} $line"
            echo ""
            count=$((count + 1))
        done < "$NODES_FILE"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# 删除所有节点
delete_all_nodes() {
    read -p "确定要删除所有保存的节点吗? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        > "$NODES_FILE"
        echo -e "${GREEN}所有节点已删除！${NC}"
    else
        echo -e "${YELLOW}取消删除${NC}"
    fi
    sleep 1
}

# 主程序
main() {
    init_config
    
    while true; do
        show_main_menu
        
        case $main_choice in
            1)
                while true; do
                    show_protocol_menu
                    case $protocol_choice in
                        1) generate_vless_reality ;;
                        2) generate_shadowsocks ;;
                        3) generate_hysteria2 ;;
                        4) generate_vmess_ws ;;
                        5) generate_trojan ;;
                        6) generate_vless_ws ;;
                        0) break ;;
                        *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
                    esac
                    
                    if [ "$protocol_choice" != "0" ]; then
                        echo ""
                        read -p "按回车键继续..."
                    fi
                done
                ;;
            2)
                view_nodes
                ;;
            3)
                delete_all_nodes
                ;;
            0)
                echo -e "${GREEN}感谢使用，再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请重试${NC}"
                sleep 1
                ;;
        esac
    done
}

# 运行主程序
main
