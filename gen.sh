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

# 获取服务器IP
get_server_ip() {
    local ip
    ip=$(curl -s4 ip.sb 2>/dev/null || curl -s4 ifconfig.me 2>/dev/null || curl -s4 icanhazip.com 2>/dev/null)
    if [ -z "$ip" ]; then
        read -p "无法自动获取IP，请手动输入服务器IP: " ip
    fi
    echo "$ip"
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
    local server_ip=$(get_server_ip)
    read -p "端口 [默认随机]: " port
    port=${port:-$(generate_port)}
    
    local uuid=$(generate_uuid)
    read -p "UUID [默认: $uuid]: " input_uuid
    uuid=${input_uuid:-$uuid}
    
    read -p "SNI [默认: $DEFAULT_SNI]: " sni
    sni=${sni:-$DEFAULT_SNI}
    
    # 生成 Reality 密钥对 (这里用随机字符串模拟，实际应使用xray生成)
    local public_key=$(generate_password 43)
    read -p "Reality Public Key [默认随机]: " input_pubkey
    public_key=${input_pubkey:-$public_key}
    
    local short_id=$(openssl rand -hex 4 2>/dev/null || generate_password 8)
    read -p "Short ID [默认: $short_id]: " input_shortid
    short_id=${input_shortid:-$short_id}
    
    read -p "节点名称 [默认: VLESS-Reality]: " node_name
    node_name=${node_name:-"VLESS-Reality"}
    node_name_encoded=$(echo -n "$node_name" | sed 's/ /%20/g')
    
    # 生成链接
    local link="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#${node_name_encoded}"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}VLESS + Reality + Vision 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}节点链接:${NC}"
    echo -e "${YELLOW}$link${NC}"
    echo ""
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  服务器: $server_ip"
    echo -e "  端口: $port"
    echo -e "  UUID: $uuid"
    echo -e "  SNI: $sni"
    echo -e "  Public Key: $public_key"
    echo -e "  Short ID: $short_id"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        save_node "VLESS-Reality" "$link"
    fi
}

# 生成 Shadowsocks 节点
generate_shadowsocks() {
    echo -e "${YELLOW}正在生成 Shadowsocks 节点...${NC}"
    echo ""
    
    local server_ip=$(get_server_ip)
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
    node_name_encoded=$(echo -n "$node_name" | sed 's/ /%20/g')
    
    # SS链接格式: ss://BASE64(method:password)@server:port#name
    local userinfo=$(base64_encode "${method}:${password}")
    local link="ss://${userinfo}@${server_ip}:${port}#${node_name_encoded}"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Shadowsocks 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}节点链接:${NC}"
    echo -e "${YELLOW}$link${NC}"
    echo ""
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  服务器: $server_ip"
    echo -e "  端口: $port"
    echo -e "  密码: $password"
    echo -e "  加密方式: $method"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        save_node "Shadowsocks" "$link"
    fi
}

# 生成 Hysteria2 节点
generate_hysteria2() {
    echo -e "${YELLOW}正在生成 Hysteria2 节点...${NC}"
    echo ""
    
    local server_ip=$(get_server_ip)
    read -p "端口 [默认随机]: " port
    port=${port:-$(generate_port)}
    
    local password=$(generate_password 32)
    read -p "密码 [默认随机]: " input_password
    password=${input_password:-$password}
    
    read -p "SNI [默认: $DEFAULT_SNI]: " sni
    sni=${sni:-$DEFAULT_SNI}
    
    read -p "跳过证书验证 [Y/n]: " insecure
    if [[ "$insecure" =~ ^[Nn]$ ]]; then
        insecure_param=""
    else
        insecure_param="&insecure=1"
    fi
    
    read -p "节点名称 [默认: HY2-Node]: " node_name
    node_name=${node_name:-"HY2-Node"}
    node_name_encoded=$(echo -n "$node_name" | sed 's/ /%20/g')
    
    # HY2链接格式
    local link="hysteria2://${password}@${server_ip}:${port}?sni=${sni}${insecure_param}#${node_name_encoded}"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Hysteria2 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}节点链接:${NC}"
    echo -e "${YELLOW}$link${NC}"
    echo ""
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  服务器: $server_ip"
    echo -e "  端口: $port"
    echo -e "  密码: $password"
    echo -e "  SNI: $sni"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        save_node "Hysteria2" "$link"
    fi
}

# 生成 VMESS + WS 节点
generate_vmess_ws() {
    echo -e "${YELLOW}正在生成 VMESS + WS 节点...${NC}"
    echo ""
    
    local server_ip=$(get_server_ip)
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
    
    # VMESS JSON格式
    local vmess_json=$(cat <<EOF
{
  "v": "2",
  "ps": "${node_name}",
  "add": "${server_ip}",
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
    
    local vmess_base64=$(echo -n "$vmess_json" | base64 | tr -d '\n')
    local link="vmess://${vmess_base64}"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}VMESS + WS 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}节点链接:${NC}"
    echo -e "${YELLOW}$link${NC}"
    echo ""
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  服务器: $server_ip"
    echo -e "  端口: $port"
    echo -e "  UUID: $uuid"
    echo -e "  WS路径: $ws_path"
    echo -e "  Host: $host"
    echo -e "  TLS: ${tls:-无}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        save_node "VMESS-WS" "$link"
    fi
}

# 生成 Trojan 节点
generate_trojan() {
    echo -e "${YELLOW}正在生成 Trojan 节点...${NC}"
    echo ""
    
    local server_ip=$(get_server_ip)
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
    node_name_encoded=$(echo -n "$node_name" | sed 's/ /%20/g')
    
    local link="trojan://${password}@${server_ip}:${port}?security=tls&sni=${sni}&type=tcp${insecure_param}#${node_name_encoded}"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Trojan 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}节点链接:${NC}"
    echo -e "${YELLOW}$link${NC}"
    echo ""
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  服务器: $server_ip"
    echo -e "  端口: $port"
    echo -e "  密码: $password"
    echo -e "  SNI: $sni"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        save_node "Trojan" "$link"
    fi
}

# 生成 VLESS + WS 节点
generate_vless_ws() {
    echo -e "${YELLOW}正在生成 VLESS + WS 节点...${NC}"
    echo ""
    
    local server_ip=$(get_server_ip)
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
    node_name_encoded=$(echo -n "$node_name" | sed 's/ /%20/g')
    
    local link="vless://${uuid}@${server_ip}:${port}?encryption=none&type=ws&host=${host}&path=$(echo -n "$ws_path" | sed 's/\//%2F/g')${tls_param}#${node_name_encoded}"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}VLESS + WS 节点生成成功！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}节点链接:${NC}"
    echo -e "${YELLOW}$link${NC}"
    echo ""
    echo -e "${CYAN}节点信息:${NC}"
    echo -e "  服务器: $server_ip"
    echo -e "  端口: $port"
    echo -e "  UUID: $uuid"
    echo -e "  WS路径: $ws_path"
    echo -e "  Host: $host"
    echo -e "  TLS: ${security}"
    echo ""
    
    read -p "是否保存该节点? [Y/n]: " save_choice
    if [[ ! "$save_choice" =~ ^[Nn]$ ]]; then
        save_node "VLESS-WS" "$link"
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
