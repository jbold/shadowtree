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

# Step 3.5: Simplify for blocker-only mode (no proxy nodes)
simplify_for_blocker_mode() {
    log_info "Simplifying config for blocker-only mode..."

    # Remove all regional node groups (HK, TW, JP, SG, KR, US)
    grep -v "^HK_Nodes = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^TW_Nodes = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^JP_Nodes = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^SG_Nodes = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^KR_Nodes = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^US_Nodes = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    # Remove service groups that reference proxy nodes
    grep -v "^AI = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^YouTube = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Netflix = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Disney+ = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Max = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^TikTok = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Spotify = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Telegram = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Twitter = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Facebook = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^PayPal = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Amazon = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Apple_Services = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Google_Services = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Microsoft_Services = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    grep -v "^Game_Services = " "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    # Remove RULE-SET entries that route to removed groups (route to DIRECT instead)
    # These external rulesets are for split-tunneling which we don't need
    sed -i '/RULE-SET.*,AI$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,YOUTUBE$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,NETFLIX$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,DISNEY+$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,MAX$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,TIKTOK$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,SPOTIFY$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,TELEGRAM$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,TWITTER$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,FACEBOOK$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,PAYPAL$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,AMAZON$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,Apple_Services$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,Google_Services$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,Microsoft_Services$/d' "$OUTPUT_FILE"
    sed -i '/RULE-SET.*,Game_Services$/d' "$OUTPUT_FILE"
    sed -i '/DOMAIN-SUFFIX.*,MAX$/d' "$OUTPUT_FILE"

    # Change RULE-SET,*,PROXY to RULE-SET,*,DIRECT (no proxy available)
    sed -i 's/,PROXY$/,DIRECT/' "$OUTPUT_FILE"

    # Change FINAL,PROXY to FINAL,DIRECT
    sed -i 's/^FINAL,PROXY$/FINAL,DIRECT/' "$OUTPUT_FILE"

    log_info "Config simplified for blocker-only mode"
}

# Step 3.6: Remove external rule references and add our own LAN rules
remove_external_rulesets() {
    log_info "Removing external RULE-SET references (unvetted)..."

    # Remove all external RULE-SET references (we maintain our own rules)
    grep -v "^RULE-SET,http" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
    mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    log_info "External RULE-SET references removed"

    # Add our own minimal LAN rules (local network should always be DIRECT)
    log_info "Adding local network rules..."

    # Insert LAN rules at the start of [Rule] section
    sed -i '/^\[Rule\]$/a \
# shadowtree: Local network (always direct)\
IP-CIDR,192.168.0.0/16,DIRECT\
IP-CIDR,10.0.0.0/8,DIRECT\
IP-CIDR,172.16.0.0/12,DIRECT\
IP-CIDR,127.0.0.0/8,DIRECT\
IP-CIDR,100.64.0.0/10,DIRECT\
DOMAIN-SUFFIX,local,DIRECT\
DOMAIN-SUFFIX,localhost,DIRECT' "$OUTPUT_FILE"

    log_info "Local network rules added"
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
        "fingerprinting.list:REJECT"
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

# Step 4.5: Strip Chinese comments and add English documentation
strip_comments() {
    log_info "Stripping upstream comments..."

    # Remove all comment lines (Chinese documentation we don't need)
    grep -v '^#' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
    mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    # Remove empty lines (cleanup)
    sed -i '/^$/d' "$OUTPUT_FILE"

    log_info "Comments stripped"
}

# Translate proxy group names that appear in Shadowrocket UI
translate_group_names() {
    log_info "Translating proxy group names..."

    # Region-based node groups
    sed -i 's|香港节点|HK_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|台湾节点|TW_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|日本节点|JP_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|新加坡节点|SG_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|韩国节点|KR_Nodes|g' "$OUTPUT_FILE"
    sed -i 's|美国节点|US_Nodes|g' "$OUTPUT_FILE"

    # Service-based groups
    sed -i 's|苹果服务|Apple_Services|g' "$OUTPUT_FILE"
    sed -i 's|谷歌服务|Google_Services|g' "$OUTPUT_FILE"
    sed -i 's|微软服务|Microsoft_Services|g' "$OUTPUT_FILE"
    sed -i 's|游戏平台|Game_Services|g' "$OUTPUT_FILE"

    log_info "Group names translated"
}

# Add our own English documentation to each section
add_section_docs() {
    log_info "Adding English section documentation..."

    # Create temp file with documentation
    local tmpfile="$OUTPUT_FILE.tmp"

    awk '
    /^\[General\]/ {
        print "# ============================================"
        print "# GENERAL SETTINGS"
        print "# Core Shadowrocket behavior configuration"
        print "# ============================================"
        print ""
        print $0
        next
    }
    /^\[Proxy\]/ {
        print ""
        print "# ============================================"
        print "# PROXY SERVERS"
        print "# Manual node definitions (most users use subscriptions instead)"
        print "# Format: Name=type,address,port,password=xxx,..."
        print "# ============================================"
        print ""
        print $0
        next
    }
    /^\[Proxy Group\]/ {
        print ""
        print "# ============================================"
        print "# PROXY GROUPS"
        print "# Node selection strategies per service/region"
        print "# Types: select (manual), url-test (auto-latency), fallback, load-balance"
        print "# ============================================"
        print ""
        print $0
        next
    }
    /^\[Rule\]/ {
        print ""
        print "# ============================================"
        print "# ROUTING RULES"
        print "# Traffic routing decisions (processed top to bottom)"
        print "# Types: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, RULE-SET, GEOIP, FINAL"
        print "# Policies: PROXY, DIRECT, REJECT, REJECT-DROP, or group name"
        print "# ============================================"
        print ""
        print $0
        next
    }
    /^\[Host\]/ {
        print ""
        print "# ============================================"
        print "# HOST MAPPINGS"
        print "# Local DNS overrides and SSID-specific DNS"
        print "# ============================================"
        print ""
        print $0
        next
    }
    { print }
    ' "$OUTPUT_FILE" > "$tmpfile"

    mv "$tmpfile" "$OUTPUT_FILE"

    log_info "Section documentation added"
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
    translate_group_names        # Must run before simplify so patterns match
    simplify_for_blocker_mode
    remove_external_rulesets     # Remove unvetted external rule lists, add our LAN rules
    insert_privacy_rulesets
    strip_comments
    add_section_docs
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
