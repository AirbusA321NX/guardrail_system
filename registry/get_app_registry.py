#!/usr/bin/env python3
"""
Module for gathering installed applications from Windows registry
"""

import csv
import winreg
import subprocess
import os
from typing import List, Dict


def get_appx_packages() -> List[Dict[str, str]]:
    """Get AppX packages using PowerShell"""
    try:
        # Use PowerShell to get AppX packages
        result = subprocess.run([
            "powershell", "-Command",
            "Get-AppxPackage | Select-Object Name, PackageFullName, Publisher, InstallLocation | ConvertTo-Json"
        ], capture_output=True, text=True, shell=True)

        if result.returncode == 0 and result.stdout.strip():
            import json
            packages = json.loads(result.stdout)
            # Ensure packages is a list
            if isinstance(packages, dict):
                packages = [packages]
            return packages
    except Exception as e:
        print(f"Error getting AppX packages: {e}")

    return []


def gather_registry_apps():
    """Gather installed applications from registry"""
    apps = []

    # Registry paths to check for installed applications
    paths = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hkey, path in paths:
        try:
            with winreg.OpenKey(hkey, path) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            # Get application information
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[
                                0] if "DisplayName" in subkey else None
                            display_version = winreg.QueryValueEx(subkey, "DisplayVersion")[
                                0] if "DisplayVersion" in subkey else None
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[
                                0] if "Publisher" in subkey else None
                            install_location = winreg.QueryValueEx(subkey, "InstallLocation")[
                                0] if "InstallLocation" in subkey else None

                            if display_name:
                                apps.append({
                                    'name': display_name,
                                    'version': display_version,
                                    'publisher': publisher,
                                    'install_location': install_location,
                                    'source': 'registry'
                                })
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            print(f"Error reading registry path {path}: {e}")

    # Add AppX packages
    appx_packages = get_appx_packages()
    for package in appx_packages:
        apps.append({
            'name': package.get('Name', ''),
            'version': '',  # AppX packages don't have version in this output
            'publisher': package.get('Publisher', ''),
            'install_location': package.get('InstallLocation', ''),
            'source': 'appx'
        })

    return apps


def export_to_csv(apps: List[Dict[str, str]], filename: str = "installed_apps.csv"):
    """Export apps to CSV file"""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['name', 'version', 'publisher',
                      'install_location', 'source']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for app in apps:
            writer.writerow(app)


if __name__ == "__main__":
    # Gather and export registry apps
    apps = gather_registry_apps()
    export_to_csv(apps)
    print(f"Exported {len(apps)} applications to installed_apps.csv")
