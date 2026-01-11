import os
import requests

# Mock the lookup process
def check_domain(domain):
    print(f"Testing domain: {domain}")
    
    # 1. Check Local Rules (Simulated)
    # We grep the build artifact because that's what the phone sees
    conf_path = os.path.expanduser('~/work/shadowtree/dist/shadowtree.conf')
    
    # Check for explicit rules in config
    with open(conf_path, 'r') as f:
        for line in f:
            if domain in line:
                if "DIRECT" in line:
                    print(f"  [MATCH] Local DIRECT Rule: {line.strip()}")
                    return "DIRECT"
                if "REJECT" in line:
                    print(f"  [MATCH] Local REJECT Rule: {line.strip()}")
                    return "REJECT"

    print("  [PASS] No local rule matched.")

    # 2. Check HaGeZi (Simulated DOMAIN-SET lookup)
    url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt"
    print(f"  [FETCH] Checking external list: {url}")
    
    try:
        r = requests.get(url)
        if r.status_code == 200:
            if domain in r.text:
                print(f"  [MATCH] Found in HaGeZi Ultimate!")
                return "REJECT (via DOMAIN-SET)"
            else:
                print("  [FAIL] Not found in HaGeZi Ultimate.")
        else:
            print(f"  [ERROR] Failed to fetch HaGeZi (Status {r.status_code})")
    except Exception as e:
        print(f"  [ERROR] Fetch failed: {e}")

    # 3. Default
    print("  [FALLBACK] Final Rule -> DIRECT")
    return "DIRECT"

# Test 0000day.com
result = check_domain("0000day.com")
print(f"\nFinal Result: {result}")
