#!/bin/bash
# shadowtree Build Script (Refactored)
# Rebuilds config from local template and rulesets.
#
# Usage: ./scripts/build.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

TEMPLATE_FILE="$PROJECT_ROOT/config/templates/base.conf"
OUTPUT_FILE="$PROJECT_ROOT/dist/shadowtree.conf"
RULESETS_DIR="$PROJECT_ROOT/config/rulesets"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }

# 1. Start with the template
# We read the template but stop before [Host] to insert rules, 
# then append [Host] at the end.
build_base() {
    log_info "Starting build from template..."
    
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "# shadowtree Privacy Config" > "$OUTPUT_FILE"
    echo "# Built: $timestamp" >> "$OUTPUT_FILE"
    echo "# Source: https://github.com/jbold/shadowtree" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    # Read everything up to [Rule]
    sed '/^\[Rule\]/q' "$TEMPLATE_FILE" >> "$OUTPUT_FILE"
}

# 2. Insert Rules
insert_rules() {
    log_info "Injecting rules..."
    
    # 2.1 LAN / Whitelist (DIRECT) - Must be first
    if [ -f "$RULESETS_DIR/lan.list" ]; then
        echo "# Local Network / Whitelist" >> "$OUTPUT_FILE"
        # Process line by line to append ,DIRECT
        while IFS= read -r line || [ -n "$line" ]; do
            # Skip comments and empty lines
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            
            # Check format
            local rule_line=""
            if [[ "$line" =~ ^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|IP-ASN|GEOIP), ]]; then
                rule_line="$line"
            else
                rule_line="DOMAIN-SUFFIX,$line"
            fi

            # Append DIRECT if no policy present
            if [[ "$rule_line" =~ ,(DIRECT|REJECT|REJECT-DROP|PROXY|Isolate)$ ]]; then
                echo "$rule_line" >> "$OUTPUT_FILE"
            else
                echo "$rule_line,DIRECT" >> "$OUTPUT_FILE"
            fi
        done < "$RULESETS_DIR/lan.list"
    fi
    
    # 2.2 Local Privacy Rules (REJECT)
    # Order doesn't strictly matter among these as long as they are REJECT
    local privacy_lists=(
        "data-brokers.list"
        "gov-surveillance.list"
        "location-brokers.list"
        "analytics.list"
        "telemetry.list"
        "advertising.list"
        "fingerprinting.list"
        "isp-tracking.list"
        "mobile-additions.list"
    )
    
    echo "" >> "$OUTPUT_FILE"
    echo "# Privacy & Security Rules" >> "$OUTPUT_FILE"
    
    for list in "${privacy_lists[@]}"; do
        if [ -f "$RULESETS_DIR/$list" ]; then
            # Read line by line to append policy if missing
            while IFS= read -r line || [ -n "$line" ]; do
                # Skip comments and empty lines
                [[ -z "$line" || "$line" =~ ^# ]] && continue
                
                # Check format
                local rule_line=""
                if [[ "$line" =~ ^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|IP-ASN|GEOIP), ]]; then
                    rule_line="$line"
                else
                    rule_line="DOMAIN-SUFFIX,$line"
                fi

                # Append REJECT if no policy present
                if [[ "$rule_line" =~ ,(DIRECT|REJECT|REJECT-DROP|PROXY|Isolate)$ ]]; then
                    echo "$rule_line" >> "$OUTPUT_FILE"
                else
                    echo "$rule_line,REJECT" >> "$OUTPUT_FILE"
                fi
            done < "$RULESETS_DIR/$list"
        fi
    done
    
    # 2.3 HaGeZi Pro (Safety Net)
    echo "" >> "$OUTPUT_FILE"
    echo "# External Safety Net (HaGeZi Pro)" >> "$OUTPUT_FILE"
    echo "RULE-SET,https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt,REJECT" >> "$OUTPUT_FILE"
    
    # 2.4 Final Fallback
    echo "" >> "$OUTPUT_FILE"
    echo "FINAL,DIRECT" >> "$OUTPUT_FILE"
}

# 3. Append Host Section
append_host() {
    log_info "Appending Host section..."
    echo "" >> "$OUTPUT_FILE"
    sed -n '/^\[Host\]/,$p' "$TEMPLATE_FILE" >> "$OUTPUT_FILE"
}

main() {
    build_base
    insert_rules
    append_host
    
    log_info "Build complete: $OUTPUT_FILE"
    log_info "Total lines: $(wc -l < "$OUTPUT_FILE")"
}

main