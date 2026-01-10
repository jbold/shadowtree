#!/bin/bash
# shadowtree Build Script
# Fetches upstream LOWERTOP config, applies privacy hardening, outputs final config
#
# Usage: ./scripts/build.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

UPSTREAM_URL="https://lowertop.github.io/Shadowrocket/lazy_group.conf"
UPSTREAM_FILE="$PROJECT_ROOT/upstream/lazy_group.conf"
OUTPUT_FILE="$PROJECT_ROOT/dist/shadowtree.conf"
DNS_OVERRIDE="$PROJECT_ROOT/overrides/dns.conf"
RULESETS_DIR="$PROJECT_ROOT/rulesets"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Step 1: Fetch upstream config
fetch_upstream() {
    log_info "Fetching upstream config from LOWERTOP..."

    if command -v curl &> /dev/null; then
        curl -sL "$UPSTREAM_URL" -o "$UPSTREAM_FILE"
    elif command -v wget &> /dev/null; then
        wget -q "$UPSTREAM_URL" -O "$UPSTREAM_FILE"
    else
        log_error "Neither curl nor wget found. Cannot fetch upstream."
        exit 1
    fi

    if [ ! -s "$UPSTREAM_FILE" ]; then
        log_error "Failed to fetch upstream config (empty file)"
        exit 1
    fi

    log_info "Upstream config saved to $UPSTREAM_FILE"
}

# Step 1.5: Automated Safety Audit
safety_audit() {
    log_info "Running safety audit on upstream config..."
    local audit_errors=0

    # 1. Check for suspicious IPs in Rules or Host (Allow 127.0.0.1, 0.0.0.0, private ranges)
    # We grep for IPv4 patterns, then filter out known safe ones
    # This is a basic heuristic to catch hardcoded proxy IPs
    local suspicious_ips=$(grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" "$UPSTREAM_FILE" | \
        grep -vE "^#" | \
        grep -v "127\.0\.0\.1" | \
        grep -v "0\.0\.0\.0" | \
        grep -v "192\.168\." | \
        grep -v "10\." | \
        grep -v "172\.16\." | \
        grep -v "223\.5\.5\.5" | \
        grep -v "119\.29\.29\.29" | \
        grep -v "8\.8\.8\.8" | \
        grep -v "8\.8\.4\.4" | \
        grep -v "1\.1\.1\.1" | \
        grep -v "9\.9\.9\.9")

    if [ -n "$suspicious_ips" ]; then
        log_error "Audit Failed: Found suspicious IP addresses in upstream:"
        echo "$suspicious_ips"
        ((audit_errors++))
    fi

    # 2. Check for MITM Hostnames (Only allow known ones)
    # Upstream usually includes *.google.cn. Anything else is suspicious.
    local mitm_hosts=$(sed -n '/\[MITM\]/,/\[/p' "$UPSTREAM_FILE" | grep "hostname =" | cut -d'=' -f2)
    for host in $mitm_hosts; do
        host=$(echo "$host" | xargs) # trim whitespace
        if [[ "$host" != "*.google.cn" && -n "$host" ]]; then
             log_error "Audit Failed: Unknown MITM hostname found: $host"
             ((audit_errors++))
        fi
    done

    # 3. Check for URL Rewrites (Only allow known Google CN fix)
    local rewrites=$(sed -n '/\[URL Rewrite\]/,/\[/p' "$UPSTREAM_FILE" | grep -vE "^\[|^\s*$|^#")
    while IFS= read -r line; do
        if [[ ! "$line" =~ google\.cn ]]; then
             log_warn "Audit Warning: Unknown URL Rewrite found: $line"
             # We assume warning for rewrites for now, as they might be benign fixes
        fi
    done <<< "$rewrites"

    if [ $audit_errors -gt 0 ]; then
        log_error "Safety audit failed with $audit_errors critical errors. Aborting build."
        exit 1
    fi

    log_info "Safety audit passed"
}

# Step 2: Apply DNS override
apply_dns_override() {
    log_info "Applying DNS override (Cloudflare + Quad9)..."

    # Read the new DNS settings
    local new_dns=$(grep "^dns-server = " "$DNS_OVERRIDE" | head -1)
    local new_fallback=$(grep "^fallback-dns-server = " "$DNS_OVERRIDE" | head -1)

    # Replace dns-server line (Chinese DNS -> Privacy DNS)
    sed -i "s|^dns-server = .*|$new_dns|" "$OUTPUT_FILE"

    # Replace fallback-dns-server
    if [ -n "$new_fallback" ]; then
        sed -i "s|^fallback-dns-server = .*|$new_fallback|" "$OUTPUT_FILE"
    fi

    log_info "DNS override applied"
}

# Step 3: Remove China-specific services
remove_china_services() {
    log_info "Removing China-specific services..."

    # Use grep -v to filter out lines containing Chinese services
    # More robust than sed with special characters
    grep -v -E "(BiliBili|NetEaseMusic|Baidu|DouBan|WeChat|Sina|Zhihu|XiaoHongShu|DouYin|China\.list)" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
    mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    # Remove 哔哩哔哩 proxy group (use grep for Unicode safety)
    grep -v "^哔哩哔哩 = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" 2>/dev/null || cp "$OUTPUT_FILE" "$OUTPUT_FILE.tmp"
    mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    # Remove GEOIP,CN,DIRECT rule
    grep -v "^GEOIP,CN,DIRECT" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
    mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    # Clean up skip-proxy (remove Chinese bank/service domains)
    # Use | as sed delimiter to avoid issues with special chars
    sed -i 's|,\*\.ccb\.com||g' "$OUTPUT_FILE"
    sed -i 's|,\*\.abchina\.com\.cn||g' "$OUTPUT_FILE"
    sed -i 's|,\*\.psbc\.com||g' "$OUTPUT_FILE"
    sed -i 's|,www\.baidu\.com||g' "$OUTPUT_FILE"
    sed -i 's|,www\.163\.com||g' "$OUTPUT_FILE"

    # Remove [URL Rewrite] and [MITM] sections (Google CN fixes not needed for US)
    # We use sed to delete from the section header to the next section or end of file
    sed -i '/^\[URL Rewrite\]/,/^\[/ { /^\[/!d; /\[URL Rewrite\]/d; }' "$OUTPUT_FILE"
    sed -i '/^\[MITM\]/,/^\[/ { /^\[/!d; /\[MITM\]/d; }' "$OUTPUT_FILE"

    # Remove confusing Chinese DNS comments
    grep -v "# dns-server =" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "# 1、DNS-over-HTTPS" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "# 2、DNS-over-HTTP" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "# 3、DNS-over-QUIC" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "# 4、DNS-over-TLS" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "# 普通 DNS 示例" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "# 加密 DNS 示例" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "dns.alidns.com" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "223.5.5.5" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    log_info "China-specific services, MITM, and comments removed"
}

# Step 4: Insert privacy rulesets
insert_privacy_rulesets() {
    log_info "Inserting privacy blocking rules..."

    local rules_to_insert=""

    # Define ruleset files and their policies
    # Format: filename:policy
    local rulesets=(
        "data-brokers.list:REJECT-DROP"
        "gov-surveillance.list:REJECT-DROP"
        "location-brokers.list:REJECT-DROP"
        "analytics.list:REJECT"
        "telemetry.list:REJECT"
        "advertising.list:REJECT"
        "isp-tracking.list:REJECT-DROP"
    )

    for ruleset_entry in "${rulesets[@]}"; do
        local filename="${ruleset_entry%%:*}"
        local policy="${ruleset_entry##*:}"
        local filepath="$RULESETS_DIR/$filename"

        if [ -f "$filepath" ] && [ -s "$filepath" ]; then
            log_info "  Adding rules from $filename ($policy)"

            # Add comment header
            rules_to_insert+="\n# shadowtree: ${filename%.list} blocking\n"

            # Read each line and format as rule
            while IFS= read -r line || [ -n "$line" ]; do
                # Skip empty lines and comments
                [[ -z "$line" || "$line" =~ ^# ]] && continue

                # If line already has rule type, use it; otherwise assume DOMAIN-SUFFIX
                if [[ "$line" =~ ^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD), ]]; then
                    rules_to_insert+="$line,$policy\n"
                else
                    rules_to_insert+="DOMAIN-SUFFIX,$line,$policy\n"
                fi
            done < "$filepath"
        fi
    done

    # Insert rules before FINAL rule (at the end of [Rule] section)
    if [ -n "$rules_to_insert" ]; then
        # Use awk to insert before FINAL line
        awk -v rules="$rules_to_insert" '
            /^FINAL,/ {
                printf "%s", rules
            }
            { print }
        ' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

        log_info "Privacy rules inserted"
    else
        log_warn "No ruleset files found or all empty"
    fi
}

# Step 4.5: Translate Chinese comments to English
translate_chinese_comments() {
    log_info "Translating Chinese comments to English..."

    # Header
    sed -i 's|# 含策略组版本，基于官方群组【懒人配置.conf.*|# Based on LOWERTOP lazy_group.conf (Official Group Version)|' "$OUTPUT_FILE"

    # General Section Translations
    sed -i 's|# Shadowrocket 快速使用方法：|# Shadowrocket Quick Start Guide:|' "$OUTPUT_FILE"
    sed -i 's|# 1、首页 > 添加节点。|# 1. Home > Add Node.|' "$OUTPUT_FILE"
    sed -i 's|# 2、设置 > 延迟测试方法，选择 CONNECT。|# 2. Settings > Latency Test Method > Select CONNECT.|' "$OUTPUT_FILE"
    sed -i 's|# 3、首页 > 连通性测试，选择可用节点连接。|# 3. Home > Connectivity Test > Select an available node to connect.|' "$OUTPUT_FILE"
    sed -i 's|# 首次启动会提示【安装 VPN 配置文件】，请点击【好】和【允许】才能正常使用。|# First run will prompt to install VPN profile. Tap Allow to proceed.|' "$OUTPUT_FILE"

    sed -i 's|# 添加/更新节点订阅失败时，可尝试以下方法：|# Troubleshooting Node Subscription Updates:|' "$OUTPUT_FILE"
    sed -i 's|# 1、首页选择一个可用节点，首页 > 全局路由 > 代理，再添加/更新节点订阅。|# 1. Select a working node, set Global Routing to Proxy, then update.|' "$OUTPUT_FILE"
    sed -i 's|# 2、切换网络连接（如关闭 VPN、蜂窝数据改 Wi-Fi、Wi-Fi 改蜂窝数据），再添加/更新节点订阅。|# 2. Switch networks (WiFi <-> Cellular) or toggle VPN off/on.|' "$OUTPUT_FILE"
    sed -i 's|# 3、检查节点订阅是否错误或失效，重新获取正确有效的订阅地址。|# 3. Verify subscription URL is correct and valid.|' "$OUTPUT_FILE"

    sed -i 's|# Shadowrocket 打开 HTTPS 解密方法：|# How to Enable HTTPS Decryption (Optional):|' "$OUTPUT_FILE"
    sed -i 's|# 1、点击“配置文件”后面 ⓘ > HTTPS 解密 > 证书 > 生成新的 CA 证书 > 安装证书。|# 1. Config > (i) > HTTPS Decryption > Generate New CA Certificate > Install.|' "$OUTPUT_FILE"
    # Escaped & for sed replacement
    sed -i 's|# 2、系统设置 > 已下载描述文件 > 安装。|# 2. iOS Settings > General > VPN and Device Management > Install Profile.|' "$OUTPUT_FILE"
    sed -i 's|# 3、系统设置 > 通用 > 关于本机 > 证书信任设置 > 开启对应 Shadowrocket 证书信任。|# 3. iOS Settings > General > About > Certificate Trust Settings > Enable trust.|' "$OUTPUT_FILE"
    sed -i 's|# “配置文件”是指（配置 > 本地文件）中正在使用的带✔️标记的配置。多设备同步时，如果配置文件已经包含证书密钥内容，建议直接安装现有证书，而不要重新生成新的 CA 证书。|# Note: Only needed for URL rewriting or specific traffic inspection. Most users can skip this.|' "$OUTPUT_FILE"

    sed -i 's|# 旁路系统。如果禁用此选项，可能会导致一些系统问题，如推送通知延迟。|# Bypass System: Keeping this enabled avoids notification delays.|' "$OUTPUT_FILE"
    sed -i 's|# 跳过代理。此选项强制这些域名或 IP 的连接范围由 Shadowrocket TUN 接口来处理，而不是 Shadowrocket 代理服务器。此选项用于解决一些应用程序的一些兼容性问题。|# Skip Proxy: Traffic to these ranges is handled by TUN interface, bypassing proxy engine.|' "$OUTPUT_FILE"
    sed -i 's|# TUN 旁路路由。Shadowrocket TUN 接口只能处理 TCP 协议。使用此选项可以绕过指定的 IP 范围，让其他协议通过。|# TUN Excluded Routes: Ranges that bypass the VPN interface entirely.|' "$OUTPUT_FILE"
    sed -i 's|# DNS 覆写。使用普通 DNS 或加密 DNS（如 DoH、DoQ、DoT 等）覆盖默认的系统 DNS。填 system 表示使用系统 DNS。|# DNS Override: Use specific DNS servers instead of system default.|' "$OUTPUT_FILE"
    
    # Missing DNS over proxy translations
    sed -i 's|# 通过代理转发 DNS 查询请求（dns over proxy）。示例：|# DNS Over Proxy Examples:|' "$OUTPUT_FILE"
    sed -i 's|# 参数说明：|# Parameters:|' "$OUTPUT_FILE"
    sed -i 's|# 1、proxy=name。指定代理服务器，名称需要 URL 编码。|# 1. proxy=name: Specify proxy server (URL encoded).|' "$OUTPUT_FILE"
    sed -i 's|# 2、ecs=子网范围。ecs 参数用于设置 EDNS Client Subnet (ECS)，向 DNS 服务器传递客户端的子网信息。ECS 允许 DNS 服务器根据指定的子网范围（而非实际客户端 IP）来返回最优结果。|# 2. ecs=subnet: Send EDNS Client Subnet to DNS server for better CDN results.|' "$OUTPUT_FILE"
    sed -i 's|# 3、ecs-override=true。ecs 参数的强制覆盖。即使客户端的实际 IP 提供了不同的地理位置，查询会强制使用 ecs 指定的子网范围。|# 3. ecs-override=true: Force use of ECS subnet regardless of client IP.|' "$OUTPUT_FILE"

    sed -i 's|# 备用 DNS。当覆写 DNS 查询失败或查询时间超过 2 秒，Shadowrocket 会自动回退备用 DNS。如需指定多个 DNS，可用逗号分隔。system 表示回退到系统 DNS。|# Fallback DNS: Used if primary DNS fails or times out (>2s).|' "$OUTPUT_FILE"
    sed -i 's|# 启用 IPv6 支持。false 表示不启用，true 表示启用。启用会同时查询 A 记录和 AAAA 记录，优先使用 IPv4 地址解析。|# IPv6 Support: Enable to query both A and AAAA records.|' "$OUTPUT_FILE"
    sed -i 's|# 首选 IPv6。优先向 IPv6 的 DNS 服务器查询 AAAA 记录，优先使用 IPv6 地址解析。false 表示不启用。|# Prefer IPv6: Prioritize AAAA records and IPv6 resolution.|' "$OUTPUT_FILE"
    sed -i 's|# 直连的域名类规则使用系统 DNS 进行查询。false 表示不启用。|# DNS Direct System: Use system DNS for DIRECT rules.|' "$OUTPUT_FILE"
    sed -i 's|# ping 数据包自动回复。|# ICMP Auto Reply: Automatically reply to ping packets.|' "$OUTPUT_FILE"
    sed -i 's|# 不开启时，「重写的 REJECT 策略」默认只有在配置模式下生效。开启后，可以令该策略在其他全局路由模式下都生效。|# Always Reject URL Rewrite: Apply REJECT rules in all routing modes.|' "$OUTPUT_FILE"
    sed -i 's|# 私有 IP 应答。如果不启用此选项，域名解析返回私有 IP，Shadowrocket 会认为该域名被劫持而强制使用代理。|# Private IP Answer: Allow DNS to return private IPs without forcing proxy.|' "$OUTPUT_FILE"
    sed -i 's|# 直连域名解析失败后使用代理。false 表示不启用。|# DNS Direct Fallback Proxy: Use proxy if DIRECT resolution fails.|' "$OUTPUT_FILE"
    sed -i 's|# TUN 包含路由。默认情况下，Shadowrocket 接口会声明自己为默认路由，但由于 Wi-Fi 接口的路由较小，有些流量可能不会通过 Shadowrocket 接口。使用此选项可以添加一个较小的路由表。|# TUN Included Routes: Specific routes to force through VPN.|' "$OUTPUT_FILE"
    sed -i 's|# 总是真实 IP。此选项要求 Shadowrocket 在 TUN 处理 DNS 请求时返回一个真实的 IP 地址而不是假的 IP 地址。|# Always Real IP: Return real IP for TUN DNS requests instead of fake IP.|' "$OUTPUT_FILE"
    sed -i 's|# DNS 劫持。有些设备或软件总是使用硬编码的 DNS 服务器，例如 Netflix 通过 Google DNS(8.8.8.8或8.8.4.4)发送请求，您可以使用此选项来劫持查询。|# DNS Hijack: Force hardcoded DNS requests (e.g., Chromecast) to use our DNS.|' "$OUTPUT_FILE"
    sed -i 's|# 当 UDP 流量匹配到规则里不支持 UDP 转发的节点策略时重新选择回退行为，可选行为包括 DIRECT、REJECT。DIRECT 表示直连转发 UDP 流量，REJECT 表示拒绝转发 UDP 流量。|# UDP Policy Fallback: Action when node doesnt support UDP (DIRECT/REJECT).|' "$OUTPUT_FILE"
    sed -i 's|# 包含配置。如“include=a.conf”表示当前配置包含另一个配置 a.conf 的内容，当前配置的优先级高于 a.conf。此选项是对配置建立包含关系，以满足同时使用多个配置的需求。|# Include Config: Merge another config file.|' "$OUTPUT_FILE"
    sed -i 's|# 此选项允许返回一个虚假的 IP 地址，如“stun-response-ip=1.1.1.1”、“stun-response-ipv6=::1”，目的是防止真实 IP 地址泄漏，提高 WebRTC 的隐私和安全性。|# STUN Response IP: Fake IP for WebRTC privacy.|' "$OUTPUT_FILE"
    sed -i 's|# 网络兼容模式。当参数的值设定为 3 时的效果等同于：设置 > 代理 > 代理类型 > None。|# Compatibility Mode: 3 = None (Settings > Proxy > Type).|' "$OUTPUT_FILE"
    sed -i 's|# 强制所有域名使用本地 DNS 解析。设置为 true 表示启用（此参数为隐藏属性，建议谨慎设置，可能导致相关域名的 CDN 失效）。|# Always IP Address: Force local DNS resolution (Caution: may break CDNs).|' "$OUTPUT_FILE"
    sed -i 's|# 代理链丢失关闭连接。若 代理链 中的中转节点丢失则 Reject 代理连接；当设置为 false 时等同于不设置该命令，即若 代理链 中的中转节点丢失则跳过中转节点直接连接落地节点使用。|# Close if Proxy Chain Missing: Reject if intermediate node fails.|' "$OUTPUT_FILE"
    sed -i 's|# 如果设备在网络环境中仅获取到 IPv6 的 DNS 而未获取到 IPv4 的 DNS，此时软件将认为网络环境是 IPv6 Only 网络，当设置为 true 时启用该命令。|# IPv6 Only if no IPv4 DNS: Detect IPv6-only networks.|' "$OUTPUT_FILE"
    sed -i 's|# QUIC协议屏蔽策略。支持使用 all-proxy、all、always-allow 对 QUIC 传输层协议进行设置。其中 all-proxy 表示只对“走代理的连接”阻断 QUIC，直连连接（DIRECT）不会被干预；all 表示对所有连接（包括直连与代理）都屏蔽 QUIC，这会完全禁止系统中一切 UDP/443 流量；always-allow 表示始终允许 QUIC，不做任何屏蔽，等同于“关闭 QUIC 屏蔽”。|# Block QUIC: Policy for QUIC/HTTP3 (all-proxy, all, always-allow).|' "$OUTPUT_FILE"
    sed -i 's|# 本地 HOST 映射对代理生效。在默认情况下，对于代理类的 DNS 解析始终在远端服务器上执行。当设置为 true 时，若存在本地 DNS 映射，Shadowrocket 将在代理连接中使用映射后的地址，而不是原始的主机名。|# Use Local Host for Proxy: Apply local [Host] mappings even for proxied connections.|' "$OUTPUT_FILE"
    sed -i 's|# allow-dns-svcb：允许 DNS SVCB 查询。系统可能会执行 SVCB 记录 DNS 查询，而不是标准的 A 记录查询。这会导致无法返回虚拟 IP 地址。因此，默认情况下禁止执行 SVCB 记录查询，以强制系统执行 A 记录查询|# Allow DNS SVCB: Allow SVCB record queries (Default: false to force A records).|' "$OUTPUT_FILE"

    # Proxy Section
    sed -i 's|# 添加本地节点。该项目的节点解析是为了兼容部分配置文件，不能当作Shadowrocket添加节点的优先选择。|# Local Nodes: Add manual server configurations here.|' "$OUTPUT_FILE"
    sed -i 's|# Shadowsocks类型：|# Shadowsocks Example:|' "$OUTPUT_FILE"
    sed -i 's|# 节点名称=ss,地址,端口,password=密码,其他参数(如method=aes-256-cfb,obfs=websocket,plugin=none)|# Name=ss,addr,port,password=pwd,method=aes-256-cfb|' "$OUTPUT_FILE"
    sed -i 's|# Vmess类型：|# VMess Example:|' "$OUTPUT_FILE"
    sed -i 's|# VLESS类型：|# VLESS Example:|' "$OUTPUT_FILE"
    sed -i 's|# HTTP/HTTPS/Socks5/Socks5 Over TLS等类型：|# HTTP/Socks5 Example:|' "$OUTPUT_FILE"
    sed -i 's|# Trojan类型：|# Trojan Example:|' "$OUTPUT_FILE"
    sed -i 's|# Hysteria类型：|# Hysteria Example:|' "$OUTPUT_FILE"
    sed -i 's|# Hysteria2类型：|# Hysteria2 Example:|' "$OUTPUT_FILE"
    sed -i 's|# TUIC类型：|# TUIC Example:|' "$OUTPUT_FILE"
    sed -i 's|# Juicity类型：|# Juicity Example:|' "$OUTPUT_FILE"
    sed -i 's|# WireGuard类型：|# WireGuard Example:|' "$OUTPUT_FILE"
    sed -i 's|# Snell类型：|# Snell Example:|' "$OUTPUT_FILE"

    # Proxy Group Section
    sed -i 's|# 代理分组类型：|# Proxy Group Types:|' "$OUTPUT_FILE"
    sed -i 's|# select:手动切换节点。|# select: Manual selection.|' "$OUTPUT_FILE"
    sed -i 's|# url-test:自动切换延迟最低节点。|# url-test: Auto-select lowest latency.|' "$OUTPUT_FILE"
    sed -i 's|# fallback:节点挂掉时自动切换其他可用节点。|# fallback: Auto-switch if node fails.|' "$OUTPUT_FILE"
    sed -i 's|# load-balance:不同规则的请求使用分组里的不同节点进行连接。|# load-balance: Round-robin/strategy based.|' "$OUTPUT_FILE"
    sed -i 's|# random:随机使用分组里的不同节点进行连接。|# random: Random selection.|' "$OUTPUT_FILE"

    sed -i 's|# policy-regex-filter表示正则式或关键词筛选，常用写法：|# Regex Filter Examples:|' "$OUTPUT_FILE"
    sed -i 's|# 1、保留节点名称含有关键词A和B的节点:|# 1. Match A AND B:|' "$OUTPUT_FILE"
    sed -i 's|# 2、保留节点名称含有关键词A或B的节点:|# 2. Match A OR B:|' "$OUTPUT_FILE"
    sed -i 's|# 3、排除节点名称含有关键词A或B的节点:|# 3. Exclude A OR B:|' "$OUTPUT_FILE"
    sed -i 's|# 4、保留节点名称含有关键词A并排除含有关键词B的节点:|# 4. Match A AND NOT B:|' "$OUTPUT_FILE"

    sed -i 's|# 代理分组其他设置参数：|# Other Group Parameters:|' "$OUTPUT_FILE"
    sed -i 's|# interval:指定间隔多长时间后需要重新发起测试。|# interval: Test frequency (seconds).|' "$OUTPUT_FILE"
    sed -i 's|# timeout:如果测试在超时前未完成，放弃测试。|# timeout: Test timeout (seconds).|' "$OUTPUT_FILE"
    sed -i 's|# tolerance:只有当新优胜者的分数高于旧优胜者的分数加上公差时，才会进行线路更换。|# tolerance: Switch threshold (ms).|' "$OUTPUT_FILE"
    sed -i 's|# url:指定要测试的URL。|# url: Test target URL.|' "$OUTPUT_FILE"

    sed -i 's|# 不含正则筛选的代理分组，示例：|# Basic Group Example:|' "$OUTPUT_FILE"
    sed -i 's|# 含正则筛选的代理分组，示例：|# Regex Group Example:|' "$OUTPUT_FILE"
    sed -i 's|# 开启订阅筛选的代理分组，示例：|# Subscription Filter Example:|' "$OUTPUT_FILE"

    # Rules Section
    sed -i 's|# 规则类型：|# Rule Types:|' "$OUTPUT_FILE"
    sed -i 's|# DOMAIN-SUFFIX：匹配请求域名的后缀。.*|# DOMAIN-SUFFIX: Matches domain suffix (e.g., example.com matches a.example.com).|' "$OUTPUT_FILE"
    sed -i 's|# DOMAIN-KEYWORD：匹配请求域名的关键词。.*|# DOMAIN-KEYWORD: Matches if keyword is present in domain.|' "$OUTPUT_FILE"
    sed -i 's|# DOMAIN：匹配请求的完整域名。.*|# DOMAIN: Exact domain match.|' "$OUTPUT_FILE"
    sed -i 's|# （当为DOMAIN、DOMAIN-SUFFIX和DOMAIN-KEYWORD类型分别设置相同的值时，只有其中一种类型会生效。）|# (Precedence: DOMAIN > DOMAIN-SUFFIX > DOMAIN-KEYWORD)|' "$OUTPUT_FILE"
    sed -i 's|# USER-AGENT：匹配用户代理字符串，支持使用通配符“*”。.*|# USER-AGENT: Match User-Agent string (supports * wildcard).|' "$OUTPUT_FILE"
    sed -i 's|# URL-REGEX：匹配URL正则式。.*|# URL-REGEX: Match URL with Regex.|' "$OUTPUT_FILE"
    sed -i 's|# IP-CIDR：匹配IPv4或IPv6地址。.*|# IP-CIDR: Match IP range (e.g., 192.168.1.0/24).|' "$OUTPUT_FILE"
    sed -i 's|# IP-ASN：匹配IP地址隶属的ASN编号。.*|# IP-ASN: Match Autonomous System Number.|' "$OUTPUT_FILE"
    sed -i 's|# RULE-SET：匹配规则集内容。.*|# RULE-SET: Load external rule file.|' "$OUTPUT_FILE"
    sed -i 's|# DOMAIN-SET：匹配域名集内容。.*|# DOMAIN-SET: Load external domain list.|' "$OUTPUT_FILE"
    sed -i 's|# SCRIPT：匹配脚本名称。.*|# SCRIPT: Execute script.|' "$OUTPUT_FILE"
    sed -i 's|# DST-PORT：匹配目标主机名的端口号。.*|# DST-PORT: Match destination port.|' "$OUTPUT_FILE"
    sed -i 's|# GEOIP：匹配IP数据库。.*|# GEOIP: Match GeoIP database country code.|' "$OUTPUT_FILE"
    sed -i 's|# FINAL：兜底策略。.*|# FINAL: Default policy if no other rules match.|' "$OUTPUT_FILE"
    sed -i 's|# AND：逻辑规则，与规则。.*|# AND: Logic AND.|' "$OUTPUT_FILE"
    sed -i 's|# NOT：逻辑规则，非规则。.*|# NOT: Logic NOT.|' "$OUTPUT_FILE"
    sed -i 's|# OR：逻辑规则，或规则。.*|# OR: Logic OR.|' "$OUTPUT_FILE"

    sed -i 's|# 规则策略：|# Rule Policies:|' "$OUTPUT_FILE"
    sed -i 's|# PROXY：代理。通过代理服务器转发流量。|# PROXY: Route through selected proxy.|' "$OUTPUT_FILE"
    sed -i 's|# DIRECT：直连。连接不经过任何代理服务器。|# DIRECT: Direct connection (no proxy).|' "$OUTPUT_FILE"
    sed -i 's|# REJECT：拒绝。返回HTTP状态码404，没有内容。|# REJECT: Return HTTP 404 (Connection Refused).|' "$OUTPUT_FILE"
    sed -i 's|# REJECT-DICT：拒绝。返回HTTP状态码200，内容为空的JSON对象。|# REJECT-DICT: Return empty JSON object.|' "$OUTPUT_FILE"
    sed -i 's|# REJECT-ARRAY：拒绝。返回HTTP状态码200，内容为空的JSON数组。|# REJECT-ARRAY: Return empty JSON array.|' "$OUTPUT_FILE"
    sed -i 's|# REJECT-200：拒绝。返回HTTP状态码200，没有内容。|# REJECT-200: Return HTTP 200 OK (Empty).|' "$OUTPUT_FILE"
    sed -i 's|# REJECT-IMG：拒绝。返回HTTP状态码200，内容为1像素GIF。|# REJECT-IMG: Return 1px GIF.|' "$OUTPUT_FILE"
    sed -i 's|# REJECT-TINYGIF：拒绝。返回HTTP状态码200，内容为1像素GIF。|# REJECT-TINYGIF: Return 1px GIF.|' "$OUTPUT_FILE"
    sed -i 's|# REJECT-DROP：拒绝。丢弃IP包。|# REJECT-DROP: Silently drop packet (Timeout).|' "$OUTPUT_FILE"
    sed -i 's|# REJECT-NO-DROP：拒绝。返回ICMP端口不可达。|# REJECT-NO-DROP: Return ICMP Port Unreachable.|' "$OUTPUT_FILE"
    sed -i 's|# 除此之外，规则策略还可以选择「代理分组」、「订阅名称」、「分组」、「节点」。|# Can also target specific Proxy Groups or Nodes.|' "$OUTPUT_FILE"

    sed -i 's|# 规则匹配的优先级：|# Match Priority:|' "$OUTPUT_FILE"
    sed -i 's|# 1.模块规则优先于配置文件规则。|# 1. Modules > Config.|' "$OUTPUT_FILE"
    sed -i 's|# 2.规则从上到下依次匹配。|# 2. Top to Bottom.|' "$OUTPUT_FILE"
    sed -i 's|# 3.域名规则优先于IP规则。|# 3. Domain > IP.|' "$OUTPUT_FILE"

    sed -i 's|# 关于屏蔽443端口的UDP流量的解释内容：.*|# Block QUIC/UDP443 to force HTTP/2 or 1.1:|' "$OUTPUT_FILE"

    sed -i 's|# 国外常用服务单独分流：.*|# International Services (Split Tunneling):|' "$OUTPUT_FILE"
    sed -i 's|# 国内常用服务单独分流：.*|# Domestic Services (Split Tunneling):|' "$OUTPUT_FILE"

    sed -i 's|# 本地局域网地址的规则集。|# LAN Ruleset:|' "$OUTPUT_FILE"
    sed -i 's|# 表示CN地区的IP分流走直连，GEOIP数据库用来判断IP是否属于CN地区。.*|# GeoIP CN Rule: Direct connection for China IPs.|' "$OUTPUT_FILE"
    sed -i 's|# 表示当其他所有规则都匹配不到时才使用FINAL规则的策略。|# FINAL Rule:|' "$OUTPUT_FILE"

    sed -i 's|# 域名指定本地值：|# Map Domain to IP:|' "$OUTPUT_FILE"
    sed -i 's|# 域名指定 DNS 服务器：|# Map Domain to DNS:|' "$OUTPUT_FILE"
    sed -i 's|# wifi名称指定 DNS 服务器，如需指定多个 DNS，可用逗号分隔：|# Map WiFi SSID to DNS:|' "$OUTPUT_FILE"
    
    # Translate specific host line example
    sed -i 's|# ssid:wifi名称 = server:1.2.3.4|# ssid:WiFi_Name = server:1.2.3.4|' "$OUTPUT_FILE"

    # Translate Proxy Example Fields (Global replace for common terms in examples)
    # Note: Using direct Chinese characters as they appear in the file
    sed -i 's|节点名称|Name|g' "$OUTPUT_FILE"
    sed -i 's|地址|Address|g' "$OUTPUT_FILE"
    sed -i 's|端口|Port|g' "$OUTPUT_FILE"
    sed -i 's|用户|User|g' "$OUTPUT_FILE"
    sed -i 's|密码|Password|g' "$OUTPUT_FILE"
    sed -i 's|其他参数|Params|g' "$OUTPUT_FILE"
    sed -i 's|如|e.g.|g' "$OUTPUT_FILE"
    sed -i 's|混淆|Obfs|g' "$OUTPUT_FILE"
    sed -i 's|协议|Protocol|g' "$OUTPUT_FILE"
    sed -i 's|私钥|PrivateKey|g' "$OUTPUT_FILE"
    sed -i 's|公钥|PublicKey|g' "$OUTPUT_FILE"
    sed -i 's|子网IP|SubnetIP|g' "$OUTPUT_FILE"
    sed -i 's|uuid值|UUID|g' "$OUTPUT_FILE"

    # Translate Proxy Group Names (Global replace to update definitions and references)
    sed -i 's|香港节点|HK_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|台湾节点|TW_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|日本节点|JP_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|新加坡节点|SG_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|韩国节点|KR_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|美国节点|US_Nodes|g' "$OUTPUT_FILE"
    
    sed -i 's|苹果服务|Apple_Services|g' "$OUTPUT_FILE"
    sed -i 's|谷歌服务|Google_Services|g' "$OUTPUT_FILE"
    sed -i 's|微软服务|Microsoft_Services|g' "$OUTPUT_FILE"
    sed -i 's|游戏平台|Game_Services|g' "$OUTPUT_FILE"

    # Translate Proxy Group Configuration Comments
    sed -i 's|名称|Name|g' "$OUTPUT_FILE"
    sed -i 's|类型|Type|g' "$OUTPUT_FILE"
    sed -i 's|策略|Policy|g' "$OUTPUT_FILE"
    sed -i 's|订阅名称|SubName|g' "$OUTPUT_FILE"
    sed -i 's|代理分组|ProxyGroup|g' "$OUTPUT_FILE"
    sed -i 's|节点|Node|g' "$OUTPUT_FILE"
    sed -i 's|测试周期|Interval|g' "$OUTPUT_FILE"
    sed -i 's|超时时间|Timeout|g' "$OUTPUT_FILE"
    sed -i 's|公差|Tolerance|g' "$OUTPUT_FILE"
    sed -i 's|指定选择的Node备注Name|SelectedNodeName|g' "$OUTPUT_FILE"
    sed -i 's|默认Policy|Default|g' "$OUTPUT_FILE"
    sed -i 's|0表示第一个Policy|0=First|g' "$OUTPUT_FILE"
    sed -i 's|1表示第二个Policy|1=Second|g' "$OUTPUT_FILE"
    sed -i 's|2表示第三个Policy|2=Third|g' "$OUTPUT_FILE"
    sed -i 's|测试Address|TestURL|g' "$OUTPUT_FILE"
    sed -i 's|正则式或关键词筛选|Regex/Keyword Filter|g' "$OUTPUT_FILE"
    sed -i 's|多个订阅时,用逗号分隔|Comma separated|g' "$OUTPUT_FILE"
    sed -i 's|省略该参数时,表示匹配对应订阅的全部Node|If omitted, matches all nodes|g' "$OUTPUT_FILE"
    sed -i 's|订阅|Subscription|g' "$OUTPUT_FILE"
    
    # Fix leftover User Agent comment - replace entire line to be safe
    sed -i 's|^# USER-AGENT：.*|# USER-AGENT: Match User-Agent string (supports * wildcard). e.g. "USER-AGENT,MicroMessenger*,DIRECT".|' "$OUTPUT_FILE"

    log_info "Translation complete"
}

# Step 5: Add shadowtree header
add_header() {
    log_info "Adding shadowtree header..."

    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local header="# shadowtree Privacy Config
# Built: $timestamp
# Base: LOWERTOP/Shadowrocket lazy_group.conf
# Modifications: Privacy DNS, tracker/surveillance blocking, CN services removed
# Source: https://github.com/jbold/shadowtree
#
"

    # Prepend header to file
    echo -e "$header$(cat "$OUTPUT_FILE")" > "$OUTPUT_FILE"
}

# Step 6: Validate syntax (basic check)
validate_syntax() {
    log_info "Validating config syntax..."

    local errors=0

    # Check required sections exist
    for section in "[General]" "[Proxy]" "[Proxy Group]" "[Rule]" "[Host]"; do
        if ! grep -q "^\\$section" "$OUTPUT_FILE"; then
            log_error "Missing section: $section"
            ((errors++))
        fi
    done

    # Check for malformed rules (basic pattern matching)
    local rule_pattern='^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|RULE-SET|GEOIP|FINAL|IP-CIDR|IP-ASN|USER-AGENT|URL-REGEX|DST-PORT|AND|NOT|OR),'

    # Check lines in [Rule] section
    local in_rule_section=0
    while IFS= read -r line; do
        if [[ "$line" == "[Rule]" ]]; then
            in_rule_section=1
            continue
        fi
        if [[ "$line" =~ ^\[ ]] && [[ "$line" != "[Rule]" ]]; then
            in_rule_section=0
            continue
        fi

        if [ $in_rule_section -eq 1 ]; then
            # Skip empty lines and comments
            [[ -z "$line" || "$line" =~ ^# ]] && continue

            if ! [[ "$line" =~ $rule_pattern ]]; then
                log_warn "Potentially malformed rule: $line"
            fi
        fi
    done < "$OUTPUT_FILE"

    if [ $errors -gt 0 ]; then
        log_error "Validation failed with $errors errors"
        return 1
    fi

    log_info "Syntax validation passed"
    return 0
}

# Main build process
main() {
    echo "========================================"
    echo "  shadowtree Build"
    echo "========================================"
    echo ""

    # Create output directory if needed
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    mkdir -p "$(dirname "$UPSTREAM_FILE")"

    # Fetch upstream
    fetch_upstream

    # Automated Audit
    safety_audit

    # Start with fresh copy
    cp "$UPSTREAM_FILE" "$OUTPUT_FILE"

    # Apply modifications
    apply_dns_override
    remove_china_services
    insert_privacy_rulesets
    translate_chinese_comments
    add_header

    # Validate
    if validate_syntax; then
        echo ""
        log_info "Build complete!"
        log_info "Output: $OUTPUT_FILE"
        echo ""

        # Show diff summary
        local upstream_lines=$(wc -l < "$UPSTREAM_FILE")
        local output_lines=$(wc -l < "$OUTPUT_FILE")
        log_info "Upstream lines: $upstream_lines"
        log_info "Output lines: $output_lines"
    else
        log_error "Build completed with warnings"
        exit 1
    fi
}

main "$@"
