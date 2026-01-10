# Upstream Config Audit

**Source**: LOWERTOP/Shadowrocket lazy_group.conf
**URL**: https://lowertop.github.io/Shadowrocket/lazy_group.conf
**Audit Date**: 2026-01-09
**Auditor**: shadowtree build system

---

## Summary

The LOWERTOP lazy_group.conf is a well-documented Shadowrocket configuration designed primarily for users in China who need to bypass the Great Firewall. It includes extensive documentation in Chinese explaining each setting.

For US-based privacy-focused users, several modifications are necessary (handled by our build script).

---

## Findings

### DNS Configuration

**Status**: ⚠️ MODIFIED BY shadowtree

Original upstream DNS servers:
- `https://doh.pub/dns-query` - Chinese DoH provider
- `https://dns.alidns.com/dns-query` - Alibaba DNS
- `223.5.5.5` - Alibaba public DNS
- `119.29.29.29` - Tencent DNSPod

**Issue**: These are Chinese DNS providers with unknown logging policies and potential CCP oversight.

**Resolution**: Replaced with Cloudflare (1.1.1.1) and Quad9 (9.9.9.9) - privacy-focused, no-log providers.

---

### DNS Hijacking

**Status**: ✅ KEPT (beneficial)

```
hijack-dns = 8.8.8.8:53,8.8.4.4:53
```

This hijacks Google DNS queries to use the configured DNS instead. This is **good for privacy** - prevents apps hardcoding Google DNS from bypassing our privacy DNS.

---

### Chinese Services (Direct Routing)

**Status**: ⚠️ REMOVED BY shadowtree

The following Chinese services were routed DIRECT (no proxy):
- BiliBili (video streaming)
- NetEase Music
- Baidu
- DouBan
- WeChat
- Sina (Weibo)
- Zhihu
- XiaoHongShu
- DouYin (Chinese TikTok)

**Issue**: These services are not needed for US users and route traffic directly through Chinese infrastructure.

**Resolution**: Removed from output config.

---

### GEOIP China Rule

**Status**: ⚠️ REMOVED BY shadowtree

```
GEOIP,CN,DIRECT
```

This routed all traffic to Chinese IPs directly (no proxy). Intended for users in China who want local traffic to go direct.

**Issue**: Not applicable for US users.

**Resolution**: Removed from output config.

---

### skip-proxy Chinese Domains

**Status**: ⚠️ REMOVED BY shadowtree

Original skip-proxy included:
- `*.ccb.com` - China Construction Bank
- `*.abchina.com.cn` - Agricultural Bank of China
- `*.psbc.com` - Postal Savings Bank of China
- `www.baidu.com`
- `www.163.com` - NetEase

**Resolution**: Removed from output config.

---

### URL Rewrites

**Status**: ✅ KEPT (beneficial)

```
^https?://(www.)?g.cn https://www.google.com 302
^https?://(www.)?google.cn https://www.google.com 302
```

Redirects Chinese Google domains to google.com. Harmless for US users.

---

### MITM Configuration

**Status**: ✅ REVIEWED - NO CONCERNS

```
hostname = *.google.cn
```

Only decrypts google.cn traffic for URL rewriting. No suspicious MITM targets.

**Note**: MITM decryption requires user to install a certificate. The config does not auto-enable this.

---

### External Rule Sets

**Status**: ✅ REVIEWED - TRUSTED SOURCES

The config uses rule sets from:
- `github.com/blackmatrix7/ios_rule_script` - Well-known, open-source rule repository
- `github.com/iab0x00/ProxyRules` - AI service rules

These are trusted community sources with transparent rule definitions.

---

### Proxy Groups

**Status**: ✅ KEPT (mostly)

The config defines proxy groups for:
- AI services (ChatGPT, Claude, etc.)
- Streaming (YouTube, Netflix, Disney+, etc.)
- Social (Twitter, Facebook, Telegram)
- Gaming platforms
- Regional node selection (HK, TW, JP, SG, KR, US)

These are useful for users with multiple proxy nodes. The 哔哩哔哩 (BiliBili) group was removed.

---

## Security Checklist

| Item | Status | Notes |
|------|--------|-------|
| Hardcoded Chinese IPs removed | ✅ | DNS servers replaced |
| Rules phoning home to Chinese services | ✅ | CN services removed |
| US-specific trackers blocked | ✅ | Added via rulesets |
| MITM certificate handling | ✅ | Only targets google.cn |
| Suspicious URL rewrites | ✅ | None found |
| Unrecognized domains | ⚠️ | Ongoing - add to research.list |
| Traffic routed through untrusted servers | ✅ | GEOIP,CN removed |

---

## Recommendations

1. **Periodic re-audit**: When pulling upstream updates, review diff for new rules
2. **Monitor research.list**: Add suspicious domains for investigation
3. **Test on device**: Verify no unexpected connections to Chinese infrastructure
4. **Review external rule sets**: Periodically check blackmatrix7 rules for changes

---

## Files Modified by Build

| Original Line | Modification |
|---------------|--------------|
| dns-server = Chinese DNS | → Cloudflare + Quad9 |
| fallback-dns-server = system | → 1.1.1.1,9.9.9.9 |
| BiliBili rules | → Removed |
| Chinese service rules | → Removed |
| GEOIP,CN,DIRECT | → Removed |
| 哔哩哔哩 proxy group | → Removed |
| skip-proxy Chinese domains | → Removed |
| [Rule] section | → Privacy rules inserted |
