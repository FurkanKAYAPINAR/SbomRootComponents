# SbomRootComponents

A Python CLI tool to fetch **direct (root) dependencies** and their **vulnerability information** from [Dependency-Track](https://dependencytrack.org/).

## Features

- 📦 Lists only **root/direct dependencies** (not transitive)
- 🔍 Shows vulnerability counts per component
- 🎯 Filter by project name or UUID
- 📊 Summary with severity breakdown
- 🔐 SSL verification toggle

## Installation

```bash
git clone https://github.com/FurkanKAYAPINAR/SbomRootComponents.git
cd SbomRootComponents
pip install -r requirements.txt
```

## Configuration

Edit `SbomRootComponents.py` and update settings:

```python
DEPENDENCY_TRACK_URL = "http://your-server:8080"
API_KEY = "your-api-key"
SSL_VERIFY = False  # Set True for production
```

### Getting API Key

1. Login to Dependency-Track
2. Go to **Administration** → **Access Management** → **Teams**
3. Select or create a team
4. Generate an **API Key**

## Usage

```bash
# List all projects with dependencies
python SbomRootComponents.py

# List specific project by name
python SbomRootComponents.py myproject

# List specific project by UUID
python SbomRootComponents.py 70ebfef4-e9c5-4358-a655-66507ba745a1
```

## Example Output

```
════════════════════════════════════════════════════════════════════════════════
📦 Project: myproject (v1.0.0)
   UUID: 70ebfef4-e9c5-4358-a655-66507ba745a1
════════════════════════════════════════════════════════════════════════════════

📊 Direct Dependencies (3 root components):

     1. pkg:npm/react@18.2.0 ✅
     2. pkg:npm/lodash@4.17.20
        └── Vulnerabilities: 🔴1 🟠2 (Total: 3)
            • CVE-2021-23337 (🔴 CRITICAL) CVSS: 9.8
            • CVE-2020-28500 (🟠 HIGH) CVSS: 7.5
            ... and 1 more vulnerabilities
     3. pkg:npm/axios@0.21.1
        └── Vulnerabilities: 🟠1 (Total: 1)
            • CVE-2021-3749 (🟠 HIGH) CVSS: 7.5

────────────────────────────────────────────────────────────────────────────────
📈 SUMMARY:
   Total Components: 3
   Vulnerabilities: 🔴 Critical: 1 | 🟠 High: 3 | 🟡 Medium: 0 | 🟢 Low: 0
```

## Requirements

- Python 3.7+
- Dependency-Track 4.x

## Author

**FurkanKAYAPINAR**

## License

MIT License
