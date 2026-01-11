import sys
import re

def process_line(line, default_policy):
    """
    Normalizes a single configuration line.
    """
    line = line.strip()
    
    # Skip comments and empty lines
    if not line or line.startswith('#'):
        return None
        
    # Check if it's already a valid rule type
    is_rule_format = ',' in line or line.startswith(('DOMAIN', 'IP-', 'GEOIP', 'USER-', 'RULE-SET', 'DOMAIN-SET'))
    
    if not is_rule_format:
        # It's a raw domain (e.g. "google.com")
        # Default to DOMAIN-SUFFIX
        line = f"DOMAIN-SUFFIX,{line}"
    
    # Check if policy exists
    # Regex: Match a comma, followed by alphabetic chars/underscores/hyphens, at end of string.
    # Note: REJECT-DROP has a hyphen.
    if re.search(r',(DIRECT|REJECT|REJECT-DROP|PROXY|Isolate|[\w_]+_Nodes|[\w_]+_Services)$', line, re.IGNORECASE):
        return line
        
    # Append default policy
    return f"{line},{default_policy}"

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 normalize.py <DEFAULT_POLICY>", file=sys.stderr)
        sys.exit(1)
        
    policy = sys.argv[1]
    
    for line in sys.stdin:
        result = process_line(line, policy)
        if result:
            print(result)

if __name__ == "__main__":
    main()