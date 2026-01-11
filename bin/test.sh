#!/bin/bash
# shadowtree Test Script
# Validates config syntax and rule assertions
#
# Usage: ./scripts/test.sh [config_file]
# If no config file specified, uses dist/shadowtree.conf

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

CONFIG_FILE="${1:-$PROJECT_ROOT/dist/shadowtree.conf}"
MUST_BLOCK="$PROJECT_ROOT/tests/rules/must_block.txt"
MUST_ALLOW="$PROJECT_ROOT/tests/rules/must_allow.txt"
REPORT_DIR="$PROJECT_ROOT/tests/reports"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((TESTS_SKIPPED++)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Extract rules from config file into a searchable format
extract_rules() {
    local config="$1"
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
            echo "$line"
        fi
    done < "$config"
}

# Check if a domain matches any rule
# Returns the policy if matched, empty if not
check_domain_rule() {
    local domain="$1"
    local rules="$2"

    # Check exact DOMAIN match
    local match=$(echo "$rules" | grep -i "^DOMAIN,$domain," | head -1)
    if [ -n "$match" ]; then
        echo "$match" | cut -d',' -f3
        return
    fi

    # Check DOMAIN-SUFFIX match (domain ends with suffix)
    while IFS= read -r rule; do
        if [[ "$rule" =~ ^DOMAIN-SUFFIX,([^,]+),(.+)$ ]]; then
            local suffix="${BASH_REMATCH[1]}"
            local policy="${BASH_REMATCH[2]}"

            # Check if domain matches suffix
            if [[ "$domain" == "$suffix" ]] || [[ "$domain" == *".$suffix" ]]; then
                echo "$policy"
                return
            fi
        fi
    done <<< "$rules"

    # Check DOMAIN-KEYWORD match
    while IFS= read -r rule; do
        if [[ "$rule" =~ ^DOMAIN-KEYWORD,([^,]+),(.+)$ ]]; then
            local keyword="${BASH_REMATCH[1]}"
            local policy="${BASH_REMATCH[2]}"

            if [[ "$domain" == *"$keyword"* ]]; then
                echo "$policy"
                return
            fi
        fi
    done <<< "$rules"

    # No match found
    echo ""
}

# Validate basic config syntax
test_syntax() {
    log_info "Testing config syntax..."

    if [ ! -f "$CONFIG_FILE" ]; then
        log_fail "Config file not found: $CONFIG_FILE"
        return 1
    fi

    local errors=0

    # Check required sections
    for section in "[General]" "[Proxy]" "[Proxy Group]" "[Rule]" "[Host]"; do
        if grep -q "^\\$section" "$CONFIG_FILE"; then
            log_pass "Section exists: $section"
        else
            log_fail "Missing section: $section"
            ((errors++))
        fi
    done

    # Check DNS is configured correctly (privacy DNS)
    if grep -q "cloudflare-dns.com\|1.1.1.1" "$CONFIG_FILE"; then
        log_pass "Privacy DNS configured (Cloudflare)"
    else
        log_fail "Privacy DNS not configured (missing Cloudflare)"
        ((errors++))
    fi

    if grep -q "quad9.net\|9.9.9.9" "$CONFIG_FILE"; then
        log_pass "Privacy DNS configured (Quad9)"
    else
        log_fail "Privacy DNS not configured (missing Quad9)"
        ((errors++))
    fi

    # Check Chinese DNS is NOT present in active config (ignore comments)
    if grep -v "^#" "$CONFIG_FILE" | grep -q "doh.pub\|dns.alidns.com\|223.5.5.5\|119.29.29.29"; then
        log_fail "Chinese DNS still present in active config"
        ((errors++))
    else
        log_pass "Chinese DNS removed from active config"
    fi

    # Check Chinese services are removed from active config (ignore comments)
    if grep -v "^#" "$CONFIG_FILE" | grep -q "BiliBili\|哔哩哔哩"; then
        log_fail "Chinese services (BiliBili) still present in active config"
        ((errors++))
    else
        log_pass "Chinese services removed from active config"
    fi

    return $errors
}

# Test must_block assertions
test_must_block() {
    log_info "Testing must_block assertions..."

    if [ ! -f "$MUST_BLOCK" ]; then
        log_skip "must_block.txt not found"
        return 0
    fi

    local rules=$(extract_rules "$CONFIG_FILE")
    local errors=0

    while IFS=',' read -r domain expected_policy category || [ -n "$domain" ]; do
        # Skip empty lines and comments
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue

        local actual_policy=$(check_domain_rule "$domain" "$rules")

        if [ -z "$actual_policy" ]; then
            log_fail "$domain ($category) - NOT BLOCKED (no rule found)"
            ((errors++))
        elif [[ "$actual_policy" == "REJECT"* ]]; then
            log_pass "$domain ($category) - blocked with $actual_policy"
        else
            log_fail "$domain ($category) - policy is $actual_policy, expected REJECT/REJECT-DROP"
            ((errors++))
        fi
    done < "$MUST_BLOCK"

    return $errors
}

# Test must_allow assertions
test_must_allow() {
    log_info "Testing must_allow assertions..."

    if [ ! -f "$MUST_ALLOW" ]; then
        log_skip "must_allow.txt not found"
        return 0
    fi

    local rules=$(extract_rules "$CONFIG_FILE")
    local errors=0

    while IFS=',' read -r domain expected_policy reason || [ -n "$domain" ]; do
        # Skip empty lines and comments
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue

        local actual_policy=$(check_domain_rule "$domain" "$rules")

        if [ -z "$actual_policy" ]; then
            # No explicit rule - will fall through to FINAL (probably PROXY)
            log_pass "$domain ($reason) - no blocking rule (falls through to FINAL)"
        elif [[ "$actual_policy" == "REJECT"* ]]; then
            log_fail "$domain ($reason) - INCORRECTLY BLOCKED with $actual_policy"
            ((errors++))
        else
            log_pass "$domain ($reason) - allowed with $actual_policy"
        fi
    done < "$MUST_ALLOW"

    return $errors
}

# Generate coverage report
generate_report() {
    log_info "Generating coverage report..."

    mkdir -p "$REPORT_DIR"
    local report="$REPORT_DIR/test-report-$(date +%Y%m%d-%H%M%S).txt"

    {
        echo "shadowtree Test Report"
        echo "======================"
        echo "Date: $(date)"
        echo "Config: $CONFIG_FILE"
        echo ""
        echo "Results:"
        echo "  Passed: $TESTS_PASSED"
        echo "  Failed: $TESTS_FAILED"
        echo "  Skipped: $TESTS_SKIPPED"
        echo ""
        echo "Ruleset Coverage:"

        # Count rules by category
        local rules=$(extract_rules "$CONFIG_FILE")
        echo "  Total rules in config: $(echo "$rules" | wc -l)"
        echo "  REJECT rules: $(echo "$rules" | grep -c ",REJECT$" || true)"
        echo "  REJECT-DROP rules: $(echo "$rules" | grep -c ",REJECT-DROP$" || true)"
        echo "  PROXY rules: $(echo "$rules" | grep -c ",PROXY$" || true)"
        echo "  DIRECT rules: $(echo "$rules" | grep -c ",DIRECT$" || true)"

    } > "$report"

    log_info "Report saved to: $report"
}

# Main test runner
main() {
    echo "========================================"
    echo "  shadowtree Test Suite"
    echo "========================================"
    echo ""
    echo "Config: $CONFIG_FILE"
    echo ""

    local total_errors=0

    # Run syntax tests
    echo ""
    echo "--- Syntax Tests ---"
    test_syntax || ((total_errors+=$?))

    # Run must_block tests
    echo ""
    echo "--- Must Block Tests ---"
    test_must_block || ((total_errors+=$?))

    # Run must_allow tests
    echo ""
    echo "--- Must Allow Tests ---"
    test_must_allow || ((total_errors+=$?))

    # Generate report
    echo ""
    generate_report

    # Summary
    echo ""
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}$TESTS_FAILED test(s) failed${NC}"
        exit 1
    fi
}

main "$@"
