# shadowtree

shadowtree is a privacy-hardened Shadowrocket configuration pipeline. It forks the popular `LOWERTOP` configuration and applies aggressive security modifications tailored for US-based, privacy-focused users.

## Features

- **Privacy-First DNS:** Replaces all Chinese DNS providers with Cloudflare (DoH) and Quad9.
- **2026 Threat Protection:** Custom rulesets for modern AI scrapers, data brokers, and location harvesters.
- **Smart TV Hardening:** Extensive blocking for Samsung, LG, and Roku telemetry.
- **Clean Configuration:** Automatically removes China-specific services (BiliBili, WeChat, Chinese banks) to reduce tracking surface.
- **Automated Pipeline:** Fetches upstream updates and merges them with your local privacy overrides.

## Project Structure

- `scripts/build.sh`: The core engine that generates the hardened config.
- `rulesets/`: Categorized blocklists (Data brokers, Surveillance, etc.).
- `overrides/`: Local DNS and General settings.
- `dist/shadowtree.conf`: The final, ready-to-use configuration file.
- `tests/`: Automated test suite to verify blocking effectiveness.

## Usage

### 1. Build the Configuration
Run the build script to fetch the latest upstream and apply modifications:
```bash
./scripts/build.sh
```

### 2. Run Tests
Verify that the privacy rules are active and blocking correctly:
```bash
./scripts/test.sh
```

### 3. Import to Shadowrocket
1. Copy the raw link to `dist/shadowtree.conf` from your GitHub repository.
2. In Shadowrocket, go to **Settings > Config > Add Config**.
3. Paste the URL and use the config.

## Development

To add new domains to the blocklist:
1. Add the domain to the appropriate file in `rulesets/`.
2. Add a test case to `tests/rules/must_block.txt`.
3. Run `./scripts/build.sh && ./scripts/test.sh`.
4. Commit and push the changes.

## Privacy Policy
This project prioritizes user privacy. We use `REJECT-DROP` for high-risk surveillance domains to ensure silent blocking without notifying the remote server.