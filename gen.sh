#!/bin/bash

# =================配置区域=================
# 节点存储文件
DB_FILE="nodes_list.txt"
# 默认 SNI
DEFAULT_SNI="itunes.apple.com"
# =========================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

# 全局变量存储 IP
IPV4_ADDR=""
IPV6_ADDR=""

# 依赖检查与安装
check_deps() {
    local install_cmd=""
    if [ -f /etc/debian_version ]; then
        install_cmd="apt-get install -y"
        update_cmd="apt-get update"
    elif [ -f /etc/redhat-release ]; then
        install_cmd="yum install -y"
        update_cmd=""
    else
        echo -e "${RED}无法检测系统版本，请手动安装 curl wget openssl uuid-runtime/util-linux jq${PLAIN}"
        return
    fi

    # 检查 curl
    if ! command -v curl &> /dev/null; then
        [[ -n "$update_cmd" ]] && $update_cmd
        $install_cmd curl
    fi

    # 检查 uuidgen
    if ! command -v uuidgen &> /dev/null; then
        echo -e "${RED}正在安装 uuidgen...${PLAIN}"
        if [ -f /etc/debian_version ]; then
            $install_cmd uuid-runtime
        else
            $install_cmd util-linux
        fi
    fi
    
    # 检查 jq
    if ! command -v jq &> /dev/null; then
         echo -e "${RED}正在安装 jq...${PLAIN}"
         $install_cmd jq
    fi
}

# 获取服务器IP (分别获取 v4 和 v6)
get_ips() {
    echo -e "${SKYBLUE}正在检测 IP 地址...${PLAIN}"
    
    # 获取 IPv4
    IPV4_ADDR=$(curl -s4m 5 https://ip.sb)
    if [[ -z "$IPV4_ADDR" ]]; then
        IPV4_ADDR=$(curl -s4m 5 https://ifconfig.me)
    fi

    # 获取 IPv6
    IPV6_ADDR=$(curl -s6m 5 https://ip.sb)
    if [[ -z "$IPV6_ADDR" ]]; then
        IPV6_ADDR=$(curl -s6m 5 https://ifconfig.me)
    fi

    if [[ -n "$IPV4_ADDR" ]]; then
        echo -e "IPv4: ${GREEN}${IPV4_ADDR}${PLAIN}"
    else
        echo -e "IPv4: ${RED}未检测到${PLAIN}"
    fi

    if [[ -n "$IPV6_ADDR" ]]; then
        echo -e "IPv6: ${GREEN}${IPV6_ADDR}${PLAIN}"
    else
        echo -e "IPv6: ${RED}未检测到${PLAIN}"
    fi
    
    if [[ -z "$IPV4_ADDR" && -z "$IPV6_ADDR" ]]; then
        echo -e "${RED}错误：无法检测到任何公网 IP，请检查网络连接。${PLAIN}"
        exit 1
    fi
}

# 生成 Reality 密钥对
get_reality_keys() {
    local temp_xray="/tmp/xray_temp"
    
    if command -v xray &> /dev/null; then
        KEYS=$(xray x25519)
    elif [ -f "$temp_xray" ]; then
        KEYS=$($temp_xray x25519)
    else
        echo -e "${YELLOW}正在下载 Xray 核心以生成密钥...${PLAIN}"
        local arch="64"
        if [[ $(uname -m) == "aarch64" ]]; then arch="arm64-v8a"; fi
        
        wget -qO temp_xray.zip "https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-${arch}.zip"
        unzip -q -o temp_xray.zip xray -d /tmp/
        mv /tmp/xray "$temp_xray"
        chmod +x "$temp_xray"
        rm temp_xray.zip
        KEYS=$($temp_xray x25519)
    fi

    PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEYS" | grep "Public" | awk '{print $3}')
}

# 辅助函数：输出并保存节点
# 参数: $1=类型, $2=IP, $3=端口, $4=链接, $5=基础备注, $6=IP类型(IPv4/IPv6)
save_and_print_link() {
    local type=$1
    local ip=$2
    local port=$3
    local link=$4
    local base_remark=$5
    local ip_ver=$6
    
    # 最终备注
    local final_remark="${base_remark}-${ip_ver}"
    
    # 替换链接中的 hash 部分(如果之前的生成没加后缀)
    # 大部分协议链接结尾是 #remark，我们这里确保链接里的备注也是新的
    # 简单处理：如果链接里包含了备注占位符，这里不作复杂替换，直接生成时指定好了即可
    # 这里我们假设传入的 link 已经包含了正确的备注或者还没加备注
    
    echo -e " [${ip_ver}] 链接: ${SKYBLUE}${link}${PLAIN}"
    echo "TYPE:${type}|REMARK:${final_remark}|LINK:${link}" >> "${DB_FILE}"
}


# 功能1: VLESS + Reality + Vision
gen_vless_reality() {
    echo -e "${SKYBLUE}正在生成 VLESS + Reality + Vision 配置...${PLAIN}"
    
    read -p "请输入端口 [443]: " PORT
    [[ -z "${PORT}" ]] && PORT="443"
    
    read -p "请输入别名 (备注): " BASE_REMARK
    [[ -z "${BASE_REMARK}" ]] && BASE_REMARK="vless"

    UUID=$(uuidgen)
    get_reality_keys
    SHORT_ID=$(openssl rand -hex 4)
    
    echo -e "\n${GREEN}=== 生成参数 (服务端配置用) ===${PLAIN}"
    echo -e "端口: ${YELLOW}${PORT}${PLAIN}"
    echo -e "UUID: ${YELLOW}${UUID}${PLAIN}"
    echo -e "Private Key: ${RED}${PRIVATE_KEY}${PLAIN}"
    echo -e "Public Key: ${YELLOW}${PUBLIC_KEY}${PLAIN}"
    echo -e "ShortId: ${YELLOW}${SHORT_ID}${PLAIN}"
    echo -e "---------------------------------------------------"

    # 生成 IPv4 链接
    if [[ -n "$IPV4_ADDR" ]]; then
        REMARK_V4="${BASE_REMARK}-IPv4"
        LINK_V4="vless://${UUID}@${IPV4_ADDR}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DEFAULT_SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${REMARK_V4}"
        save_and_print_link "VLESS" "$IPV4_ADDR" "$PORT" "$LINK_V4" "$BASE_REMARK" "IPv4"
    fi

    # 生成 IPv6 链接 (注意 IPv6 地址需要加 [])
    if [[ -n "$IPV6_ADDR" ]]; then
        REMARK_V6="${BASE_REMARK}-IPv6"
        LINK_V6="vless://${UUID}@[${IPV6_ADDR}]:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DEFAULT_SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${REMARK_V6}"
        save_and_print_link "VLESS" "$IPV6_ADDR" "$PORT" "$LINK_V6" "$BASE_REMARK" "IPv6"
    fi
    echo -e "---------------------------------------------------"
}

# 功能2: Shadowsocks
gen_shadowsocks() {
    echo -e "${SKYBLUE}正在生成 Shadowsocks 配置...${PLAIN}"
    
    read -p "请输入端口: " PORT
    read -p "请输入密码 (留空随机): " PASS
    [[ -z "${PASS}" ]] && PASS=$(openssl rand -base64 16)
    
    read -p "请输入别名 (备注): " BASE_REMARK
    [[ -z "${BASE_REMARK}" ]] && BASE_REMARK="ss"

    METHOD="aes-256-gcm"
    CREDENTIALS=$(echo -n "${METHOD}:${PASS}" | base64 -w 0)

    echo -e "\n${GREEN}=== 生成参数 ===${PLAIN}"
    echo -e "密码: ${YELLOW}${PASS}${PLAIN}"
    echo -e "加密: ${YELLOW}${METHOD}${PLAIN}"
    echo -e "---------------------------------------------------"

    # IPv4
    if [[ -n "$IPV4_ADDR" ]]; then
        REMARK_V4="${BASE_REMARK}-IPv4"
        LINK_V4="ss://${CREDENTIALS}@${IPV4_ADDR}:${PORT}#${REMARK_V4}"
        save_and_print_link "SS" "$IPV4_ADDR" "$PORT" "$LINK_V4" "$BASE_REMARK" "IPv4"
    fi

    # IPv6
    if [[ -n "$IPV6_ADDR" ]]; then
        REMARK_V6="${BASE_REMARK}-IPv6"
        # SS 链接中 IPv6 也建议加 []
        LINK_V6="ss://${CREDENTIALS}@[${IPV6_ADDR}]:${PORT}#${REMARK_V6}"
        save_and_print_link "SS" "$IPV6_ADDR" "$PORT" "$LINK_V6" "$BASE_REMARK" "IPv6"
    fi
    echo -e "---------------------------------------------------"
}

# 功能3: Hysteria2
gen_hysteria2() {
    echo -e "${SKYBLUE}正在生成 Hysteria2 配置...${PLAIN}"
    
    read -p "请输入端口: " PORT
    read -p "请输入密码 (留空随机): " PASS
    [[ -z "${PASS}" ]] && PASS=$(openssl rand -hex 8)
    
    read -p "请输入别名 (备注): " BASE_REMARK
    [[ -z "${BASE_REMARK}" ]] && BASE_REMARK="hy2"

    echo -e "\n${GREEN}=== 生成参数 ===${PLAIN}"
    echo -e "密码: ${YELLOW}${PASS}${PLAIN}"
    echo -e "---------------------------------------------------"

    # IPv4
    if [[ -n "$IPV4_ADDR" ]]; then
        REMARK_V4="${BASE_REMARK}-IPv4"
        LINK_V4="hysteria2://${PASS}@${IPV4_ADDR}:${PORT}?sni=${DEFAULT_SNI}&insecure=1#${REMARK_V4}"
        save_and_print_link "HY2" "$IPV4_ADDR" "$PORT" "$LINK_V4" "$BASE_REMARK" "IPv4"
    fi

    # IPv6
    if [[ -n "$IPV6_ADDR" ]]; then
        REMARK_V6="${BASE_REMARK}-IPv6"
        # Hy2 链接 IPv6 加 []
        LINK_V6="hysteria2://${PASS}@[${IPV6_ADDR}]:${PORT}?sni=${DEFAULT_SNI}&insecure=1#${REMARK_V6}"
        save_and_print_link "HY2" "$IPV6_ADDR" "$PORT" "$LINK_V6" "$BASE_REMARK" "IPv6"
    fi
    echo -e "---------------------------------------------------"
}

# 功能4: 查看已存节点
view_nodes() {
    if [[ ! -f "${DB_FILE}" ]]; then
        echo -e "${RED}没有找到已保存的节点记录。${PLAIN}"
        return
    fi
    
    echo -e "${GREEN}=== 已保存节点列表 ===${PLAIN}"
    local i=1
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            TYPE=$(echo "$line" | awk -F'|' '{print $1}' | cut -d':' -f2)
            REMARK=$(echo "$line" | awk -F'|' '{print $2}' | cut -d':' -f2)
            LINK=$(echo "$line" | awk -F'|' '{print $3}' | cut -d':' -f2-)
            
            # 根据备注着色区分 v4 和 v6
            if [[ "$REMARK" == *"IPv6"* ]]; then
                COLOR=$SKYBLUE
            else
                COLOR=$YELLOW
            fi
            
            echo -e "${GREEN}[${i}]${PLAIN} 协议: ${TYPE} | 备注: ${COLOR}${REMARK}${PLAIN}"
            echo -e "    ${LINK}"
            echo ""
            ((i++))
        fi
    done < "${DB_FILE}"
}

# 菜单逻辑
menu() {
    clear
    echo -e "################################################"
    echo -e "#        ${GREEN}双栈节点链接一键生成器${PLAIN}            #"
    echo -e "################################################"
    if [[ -n "$IPV4_ADDR" ]]; then echo -e "IPv4: ${GREEN}${IPV4_ADDR}${PLAIN}"; fi
    if [[ -n "$IPV6_ADDR" ]]; then echo -e "IPv6: ${GREEN}${IPV6_ADDR}${PLAIN}"; fi
    echo -e "SNI : ${DEFAULT_SNI}"
    echo -e "------------------------------------------------"
    echo -e "${GREEN}1.${PLAIN} 生成 VLESS + Reality + Vision"
    echo -e "${GREEN}2.${PLAIN} 生成 Shadowsocks"
    echo -e "${GREEN}3.${PLAIN} 生成 Hysteria2"
    echo -e "${GREEN}4.${PLAIN} 查看所有节点"
    echo -e "${GREEN}0.${PLAIN} 退出"
    echo -e "------------------------------------------------"
    read -p "请选择: " choice

    case "$choice" in
        1) gen_vless_reality ;;
        2) gen_shadowsocks ;;
        3) gen_hysteria2 ;;
        4) view_nodes ;;
        0) exit 0 ;;
        *) echo -e "${RED}输入错误${PLAIN}" ;;
    esac
}

# 主程序
check_deps
get_ips
while true; do
    menu
    read -p "按回车键返回主菜单..."
done
