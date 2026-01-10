# ShadowTree Project

Shadowrocket config repo forked from LOWERTOP/Shadowrocket, hardened for US-based privacy-focused user.

## Project Goals

1. **Privacy-first DNS**: Replace Chinese DNS with Western privacy-focused alternatives
2. **Comprehensive blocking**: Ads, trackers, analytics, data brokers, government surveillance
3. **Upstream compatibility**: Maintain ability to pull LOWERTOP updates via build script
4. **Transparency**: Audit and document all Chinese upstream rules for safety

---

## Threat Model

Block aggressively by category. These lists are non-exhaustive — actively research and add new entities as discovered.

### Data Brokers & People Search
Companies that collect, aggregate, and sell personal information. Includes but not limited to:
- Consumer data aggregators (Acxiom, Oracle Data Cloud, LexisNexis, Experian marketing, etc.)
- People search engines (Spokeo, Whitepages, BeenVerified, Intelius, etc.)
- Identity resolution platforms (LiveRamp, Tapad, Drawbridge, etc.)
- **Add any company whose business model is selling personal data**

### Government, Intelligence & Law Enforcement Adjacent
Private companies that contract with government/intel agencies for surveillance, data analysis, or tracking. Includes but not limited to:
- Palantir, Clearview AI, Babel Street, Hawk Analytics
- ShadowDragon, Cobwebs Technologies, Voyager Labs
- NSO Group infrastructure, Cellebrite cloud services
- **Add any company providing surveillance tech to government entities**

### Advertising & Cross-Site Tracking
Networks that track users across sites/apps for ad targeting. Includes but not limited to:
- Major ad platforms (Google Ads, Meta, Amazon, Microsoft, The Trade Desk, Criteo)
- Retargeting networks (Taboola, Outbrain, AdRoll)
- Mobile ad networks (AppLovin, Unity Ads, IronSource, Appsflyer)
- **Add any domain serving ads or tracking for ad purposes**

### Analytics & Session Recording
Services that track user behavior on websites/apps. Includes but not limited to:
- Analytics platforms (Google Analytics, Adobe Analytics, Mixpanel, Amplitude, Segment, Heap)
- Session replay (Hotjar, FullStory, LogRocket, Mouseflow)
- Product analytics (Pendo, WalkMe, Appcues)
- **Add any service that records or analyzes user behavior**

### Device & OS Telemetry
Built-in tracking from operating systems and devices. Includes but not limited to:
- Apple telemetry endpoints
- Microsoft/Windows telemetry
- Smart TV beacons (Samsung, LG, Roku, Vizio, etc.)
- IoT device phone-home endpoints
- **Add any device manufacturer telemetry**

### Location Data Brokers
Companies that buy/sell location data harvested from apps. Includes but not limited to:
- SafeGraph, Placer.ai, Foursquare/Factual
- X-Mode/Outlogic, Cuebiq, Near, GroundTruth
- Gravy Analytics, Veraset
- **Add any company dealing in location data**

### ISP & Network-Level Tracking
- ISP injected tracking (Xfinity, AT&T, Verizon supercookies)
- Deep packet inspection infrastructure
- **Add any ISP-level surveillance**

### Foreign State-Adjacent (Non-China)
- Israeli surveillance tech companies
- UAE/Saudi-linked tracking
- Russian ad networks
- **Add any foreign state-linked tracking infrastructure**

### Uncategorized / Research Needed
Domains flagged for investigation. Move to appropriate category once identified.

---

## DNS Configuration

### Use (privacy-focused, no-log)
```
dns-server = https://cloudflare-dns.com/dns-query,https://dns.quad9.net/dns-query,1.1.1.1,9.9.9.9
```

### Block/Avoid
- Google DNS (8.8.8.8, dns.google) - logs, ad profile
- OpenDNS - Cisco owned, logs
- Any Chinese DNS (Alibaba, Tencent, Baidu, etc.)

---

## File Structure

```
├── GEMINI.md                  # This file - project context
├── lazy_group.conf            # Main config (upstream from LOWERTOP)
├── lazy.conf                  # Simple config (upstream from LOWERTOP)
├── scripts/
│   ├── build.sh               # Pulls upstream, applies our customizations
│   └── test.sh                # Runs all tests
├── overrides/
│   ├── dns.conf               # Our DNS settings
│   └── general.conf           # Other [General] overrides
├── audit/
│   └── upstream-review.md     # Security audit of Chinese upstream config
├── rulesets/
│   ├── data-brokers.list      # Data broker domains
│   ├── gov-surveillance.list  # Government/intel adjacent
│   ├── analytics.list         # Analytics & session recording
│   ├── advertising.list       # Ad networks beyond upstream
│   ├── telemetry.list         # OS/device telemetry
│   ├── location-brokers.list  # Location data companies
│   ├── isp-tracking.list      # ISP-level tracking
│   └── research.list          # Unverified, needs investigation
├── tests/
│   ├── syntax/                # Config parsing validation
│   ├── dns/                   # DNS server verification
│   ├── rules/
│   │   ├── must_block.txt     # Domains that MUST be blocked
│   │   └── must_allow.txt     # Domains that MUST NOT be blocked
│   ├── integration/           # Live resolution tests
│   └── reports/               # Coverage reports
└── dist/
    └── shadowtree.conf        # Final built config for Shadowrocket
```

---

## Build Script Behavior

`scripts/build.sh` should:
1. Fetch latest lazy_group.conf from LOWERTOP
2. Replace dns-server line with our privacy DNS
3. Append our additional rule sets to [Rule] section
4. Validate config syntax
5. Output to dist/shadowtree.conf
6. Log what changed from upstream

---

## Coding Conventions

- **Comments**: Use liberally, explain why not just what
- **Rule format**: `TYPE,domain-or-pattern,POLICY`
- **Prefer DOMAIN-SUFFIX**: Catches subdomains automatically
- **REJECT-DROP**: For surveillance (silent, no response back)
- **REJECT**: For ads (faster, returns 404)
- **Group rules**: Use comment headers by category
- **Source attribution**: Note where rules came from

---

## Upstream Audit Checklist

Review LOWERTOP config for:
- [ ] Hardcoded Chinese IPs to remove/flag
- [ ] Rules that phone home to Chinese services
- [ ] Missing US-specific trackers
- [ ] MITM certificate handling
- [ ] Suspicious URL rewrites
- [ ] Unrecognized domains (research needed)
- [ ] Anything that routes traffic through untrusted servers

---

## Test-Driven Development

All config changes must be testable. Tests run before merging any changes.

### Test Categories

1. **Syntax** — Config parses without errors
2. **DNS** — Queries route to correct privacy-focused servers
3. **Rule Matching** — Domain X hits expected policy (REJECT, REJECT-DROP, DIRECT, PROXY)
4. **False Positives** — Legitimate domains not blocked
5. **Coverage** — % of threat model categories with active rules

### Test Data Format

```
# must_block.txt
# domain,policy,category
doubleclick.net,REJECT,advertising
google-analytics.com,REJECT,analytics
palantir.com,REJECT-DROP,gov-surveillance
spokeo.com,REJECT-DROP,data-broker
safegraph.com,REJECT-DROP,location-broker

# must_allow.txt
# domain,policy,reason
github.com,PROXY,legitimate-dev
cloudflare.com,DIRECT,dns-provider
signal.org,PROXY,secure-messaging
```

### Test Runner

`scripts/test.sh` should:
1. Validate config syntax
2. Run all must_block assertions
3. Run all must_allow assertions
4. Report pass/fail with exit code
5. Generate coverage report

### CI Behavior

- Tests run on every commit
- PR blocked if tests fail
- Coverage report posted to PR

### Rule Matching Logic

Since Shadowrocket has no CLI, we parse the config ourselves to simulate rule matching. Match priority:
1. DOMAIN (exact match)
2. DOMAIN-SUFFIX (suffix match)
3. DOMAIN-KEYWORD (contains)
4. RULE-SET (external list)
5. GEOIP
6. FINAL (fallback)

---

## Testing Checklist (Manual, On-Device)

After building config:
1. Import to Shadowrocket
2. Verify DNS: https://1.1.1.1/help
3. Test ad blocking: https://d3ward.github.io/toolz/adblock.html
4. Check for leaks: https://browserleaks.com
5. DNS leak test: https://dnsleaktest.com
6. WebRTC leak test: https://browserleaks.com/webrtc

---

## Resources & Upstream Sources

- LOWERTOP (upstream): https://github.com/LOWERTOP/Shadowrocket
- blackmatrix7 rules: https://github.com/blackmatrix7/ios_rule_script
- hagezi blocklists: https://github.com/hagezi/dns-blocklists
- StevenBlack hosts: https://github.com/StevenBlack/hosts
- EasyList/EasyPrivacy: https://easylist.to
- AdGuard filters: https://github.com/AdguardTeam/AdguardFilters
- Peter Lowe's list: https://pgl.yoyo.org/adservers/
- OISD blocklist: https://oisd.nl

---

## Contributing New Rules

When adding domains:
1. Verify the domain is actually tracking/malicious
2. Document the source or evidence
3. Place in appropriate category list
4. If unsure, add to research.list first
5. Test that blocking doesn't break legitimate functionality

---

## Gemini CLI Instructions

When working on this project:

### First Run
1. Review this entire GEMINI.md for context
2. Examine lazy_group.conf to understand the upstream config format
3. Identify Chinese DNS entries that need replacement

### Common Tasks

**Update DNS settings:**
```
Find the dns-server line in lazy_group.conf and replace with our privacy DNS from the DNS Configuration section above
```

**Add new blocking rules:**
```
Add domains to the appropriate ruleset file in rulesets/, then update must_block.txt with test cases
```

**Pull upstream updates:**
```
Run scripts/build.sh to fetch latest from LOWERTOP and apply our overrides
```

**Run tests:**
```
Run scripts/test.sh and ensure all assertions pass before committing
```

### Do Not
- Use Google DNS or any Chinese DNS providers
- Remove blocking rules without documenting why
- Commit without running tests
- Trust upstream blindly — audit changes
