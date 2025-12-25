#!/usr/bin/env python3
"""
SbomRootComponents - Dependency-Track API Client
Lists only ROOT (direct) dependencies and vulnerability information.

Author: FurkanKAYAPINAR
License: MIT
Repository: https://github.com/FurkanKAYAPINAR/SbomRootComponents

Usage:
    python SbomRootComponents.py                    # Lists all projects
    python SbomRootComponents.py <project_uuid>     # Lists specific project
    python SbomRootComponents.py <project_name>     # Searches by project name
"""

import requests
import sys
import urllib3
from typing import Optional, List, Dict, Any

__author__ = "FurkanKAYAPINAR"
__version__ = "1.0.0"
__license__ = "MIT"

# Suppress SSL warnings (when verify=False is used)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ⚠️ SETTINGS
DEPENDENCY_TRACK_URL = "http://127.0.0.1:8080"  # Change to your Dependency-Track URL
API_KEY = "YOUR_API_KEY"  # Change to your API key
SSL_VERIFY = False  # SSL verification: True = enabled, False = disabled


class DependencyTrackClient:
    """Dependency-Track API Client for fetching root dependencies and vulnerabilities."""
    
    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.headers = {
            'X-Api-Key': api_key,
            'Content-Type': 'application/json'
        }
    
    def get_projects(self) -> List[Dict[str, Any]]:
        """Fetches all projects."""
        all_projects = []
        page = 1
        
        while True:
            response = requests.get(
                f"{self.base_url}/api/v1/project",
                headers=self.headers,
                params={'pageNumber': page, 'pageSize': 100},
                timeout=30,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            projects = response.json()
            
            if not projects:
                break
            all_projects.extend(projects)
            if len(projects) < 100:
                break
            page += 1
        
        return all_projects
    
    def get_project_by_uuid(self, uuid: str) -> Optional[Dict[str, Any]]:
        """Fetches project by UUID."""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/project/{uuid}",
                headers=self.headers,
                timeout=30,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except:
            return None
    
    def find_project_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Searches project by name."""
        projects = self.get_projects()
        for project in projects:
            if project.get('name', '').lower() == name.lower():
                return project
        return None
    
    def get_direct_dependencies(self, project_uuid: str) -> List[Dict[str, Any]]:
        """Fetches only ROOT (direct) dependencies."""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/dependencyGraph/project/{project_uuid}/directDependencies",
                headers=self.headers,
                timeout=30,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"   ⚠️ Direct dependencies API error: {e}")
            return []
    
    def get_component_vulnerabilities(self, component_uuid: str) -> List[Dict[str, Any]]:
        """Fetches vulnerabilities for a specific component."""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/vulnerability/component/{component_uuid}",
                headers=self.headers,
                timeout=30,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except:
            return []
    
    def format_severity(self, severity: str) -> str:
        """Formats severity with emoji."""
        severity_map = {
            'CRITICAL': '🔴 CRITICAL',
            'HIGH': '🟠 HIGH',
            'MEDIUM': '🟡 MEDIUM',
            'LOW': '🟢 LOW',
            'UNASSIGNED': '⚪ UNASSIGNED',
            'INFO': '🔵 INFO'
        }
        return severity_map.get(severity.upper(), severity)
    
    def print_project_dependencies(self, project: Dict[str, Any]) -> None:
        """Prints project's ROOT dependencies and vulnerabilities."""
        name = project.get('name', 'Unknown')
        version = project.get('version', '-')
        uuid = project.get('uuid', '')
        
        print(f"\n{'═' * 80}")
        print(f"📦 Project: {name} (v{version})")
        print(f"   UUID: {uuid}")
        print(f"{'═' * 80}")
        
        direct_deps = self.get_direct_dependencies(uuid)
        
        if not direct_deps:
            print("   ⚠️ Direct dependency not found")
            return
        
        print(f"\n📊 Direct Dependencies ({len(direct_deps)} root components):\n")
        
        total_vulns = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for idx, dep in enumerate(direct_deps, 1):
            purl = dep.get('purl', '')
            comp_name = dep.get('name', 'Unknown')
            comp_version = dep.get('version', '?')
            group = dep.get('group', '')
            comp_uuid = dep.get('uuid', '')
            
            # Component name
            if purl:
                display_name = purl
            elif group:
                display_name = f"{group}:{comp_name}@{comp_version}"
            else:
                display_name = f"{comp_name}@{comp_version}"
            
            # Get vulnerabilities
            vulns = self.get_component_vulnerabilities(comp_uuid)
            
            if vulns:
                # Calculate vulnerability counts
                vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                for v in vulns:
                    sev = v.get('severity', 'UNASSIGNED').upper()
                    if sev in vuln_counts:
                        vuln_counts[sev] += 1
                        total_vulns[sev] += 1
                
                # Vulnerability summary
                vuln_summary = []
                if vuln_counts['CRITICAL'] > 0:
                    vuln_summary.append(f"🔴{vuln_counts['CRITICAL']}")
                if vuln_counts['HIGH'] > 0:
                    vuln_summary.append(f"🟠{vuln_counts['HIGH']}")
                if vuln_counts['MEDIUM'] > 0:
                    vuln_summary.append(f"🟡{vuln_counts['MEDIUM']}")
                if vuln_counts['LOW'] > 0:
                    vuln_summary.append(f"🟢{vuln_counts['LOW']}")
                
                vuln_str = " ".join(vuln_summary) if vuln_summary else "✅"
                print(f"   {idx:3}. {display_name}")
                print(f"        └── Vulnerabilities: {vuln_str} (Total: {len(vulns)})")
                
                # Show first 3 vulnerabilities
                for v in vulns[:3]:
                    vuln_id = v.get('vulnId', 'N/A')
                    severity = v.get('severity', 'UNASSIGNED')
                    cvss = v.get('cvssV3BaseScore') or v.get('cvssV2BaseScore') or '-'
                    print(f"            • {vuln_id} ({self.format_severity(severity)}) CVSS: {cvss}")
                
                if len(vulns) > 3:
                    print(f"            ... and {len(vulns) - 3} more vulnerabilities")
            else:
                print(f"   {idx:3}. {display_name} ✅")
        
        print(f"\n{'─' * 80}")
        print(f"📈 SUMMARY:")
        print(f"   Total Components: {len(direct_deps)}")
        print(f"   Vulnerabilities: 🔴 Critical: {total_vulns['CRITICAL']} | 🟠 High: {total_vulns['HIGH']} | 🟡 Medium: {total_vulns['MEDIUM']} | 🟢 Low: {total_vulns['LOW']}")
    
    def list_all_projects(self) -> None:
        """Lists all projects and their ROOT dependencies."""
        projects = self.get_projects()
        
        if not projects:
            print("⚠️ No projects found.")
            return
        
        print(f"\n🔍 Found {len(projects)} projects.\n")
        
        for project in projects:
            self.print_project_dependencies(project)
        
        print(f"\n{'═' * 80}")
        print("✅ Listing completed.")
        print(f"{'═' * 80}\n")


def main():
    """Main entry point."""
    client = DependencyTrackClient(DEPENDENCY_TRACK_URL, API_KEY, verify_ssl=SSL_VERIFY)
    
    if len(sys.argv) > 1:
        project_key = sys.argv[1]
        
        if len(project_key) == 36 and project_key.count('-') == 4:
            project = client.get_project_by_uuid(project_key)
        else:
            project = client.find_project_by_name(project_key)
        
        if project:
            client.print_project_dependencies(project)
        else:
            print(f"❌ Project not found: {project_key}")
            print("\n📋 Available projects:")
            for p in client.get_projects():
                print(f"   - {p.get('name')} ({p.get('uuid')})")
    else:
        client.list_all_projects()


if __name__ == "__main__":
    main()
