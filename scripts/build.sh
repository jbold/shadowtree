#!/bin/bash
# ShadowTree Build Script
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

    log_info "China-specific services removed"
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
            rules_to_insert+="\n# ShadowTree: ${filename%.list} blocking\n"

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

# Step 5: Add ShadowTree header
add_header() {
    log_info "Adding ShadowTree header..."

    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local header="# ShadowTree Privacy Config
# Built: $timestamp
# Base: LOWERTOP/Shadowrocket lazy_group.conf
# Modifications: Privacy DNS, tracker/surveillance blocking, CN services removed
# Source: https://github.com/YOUR_USERNAME/ShadowTree
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
    echo "  ShadowTree Build"
    echo "========================================"
    echo ""

    # Create output directory if needed
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    mkdir -p "$(dirname "$UPSTREAM_FILE")"

    # Fetch upstream
    fetch_upstream

    # Start with fresh copy
    cp "$UPSTREAM_FILE" "$OUTPUT_FILE"

    # Apply modifications
    apply_dns_override
    remove_china_services
    insert_privacy_rulesets
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
