from androguard.misc import AnalyzeAPK
from lxml import etree
import os
import json
from datetime import datetime
from typing import List, Dict, Any
import matplotlib.pyplot as plt


class APKScanner:
    def __init__(self, apk_path: str) -> None:
        self.apk_path: str = apk_path
        self.apk, self.dex_files, self.analysis = AnalyzeAPK(apk_path)
        self.vulnerabilities: List[Dict[str, str]] = []
        self.manifest: etree.Element = self.apk.get_android_manifest_xml()

    def is_component_exported(self, component_tag: str, component_name: str) -> bool:
        for component in self.manifest.findall(f".//{component_tag}"):
            if component.get("{http://schemas.android.com/apk/res/android}name") == component_name:
                exported = component.get("{http://schemas.android.com/apk/res/android}exported")
                if exported == "true":
                    return True
                intent_filters = component.findall("./intent-filter")
                if intent_filters:
                    return True
        return False

    def scan_permissions(self) -> None:
        dangerous_permissions: List[str] = [
            # Phone and SMS related permissions
            "android.permission.READ_PHONE_STATE",  # Access phone state including phone number, cellular network info
            "android.permission.READ_PHONE_NUMBERS", # Access phone numbers from device
            "android.permission.PROCESS_OUTGOING_CALLS", # Monitor/redirect/prevent outgoing calls
            "android.permission.CALL_PHONE", # Initiate phone calls without user intervention
            "android.permission.ANSWER_PHONE_CALLS", # Answer incoming phone calls programmatically
            "android.permission.ADD_VOICEMAIL", # Add voicemails to the system
            "android.permission.READ_SMS", # Read SMS messages
            "android.permission.SEND_SMS", # Send SMS messages
            "android.permission.RECEIVE_SMS", # Receive SMS messages
            "android.permission.READ_CALL_LOG", # Read phone call log
            "android.permission.WRITE_CALL_LOG", # Modify phone call log

            # Location related permissions
            "android.permission.ACCESS_FINE_LOCATION", # Precise location access (GPS)
            "android.permission.ACCESS_COARSE_LOCATION", # Approximate location access (Network-based)
            "android.permission.ACCESS_BACKGROUND_LOCATION", # Access location in background
            
            # Storage related permissions
            "android.permission.WRITE_EXTERNAL_STORAGE", # Write to external storage
            "android.permission.READ_EXTERNAL_STORAGE", # Read from external storage
            "android.permission.ACCESS_MEDIA_LOCATION", # Access media files location metadata
            "android.permission.MANAGE_EXTERNAL_STORAGE", # All files access (CRITICAL)
            
            # Contact and Calendar related permissions
            "android.permission.READ_CONTACTS", # Read contacts data
            "android.permission.WRITE_CONTACTS", # Modify contacts data
            "android.permission.GET_ACCOUNTS", # Access list of accounts
            "android.permission.READ_CALENDAR", # Read calendar events
            "android.permission.WRITE_CALENDAR", # Add/modify calendar events
            
            # Hardware related permissions
            "android.permission.CAMERA", # Access camera
            "android.permission.RECORD_AUDIO", # Record audio
            "android.permission.BODY_SENSORS", # Access body sensors (heart rate etc)
            "android.permission.ACTIVITY_RECOGNITION", # Detect user's physical activity
            "android.permission.BLUETOOTH", # Connect to bluetooth devices
            "android.permission.BLUETOOTH_ADMIN", # Discover and pair bluetooth devices
            "android.permission.NFC", # Perform NFC communication
            "android.permission.UWB_RANGING", # Ultra-wideband ranging
            
            # Biometric related permissions
            "android.permission.USE_BIOMETRIC", # Use biometric hardware
            "android.permission.USE_FINGERPRINT", # Use fingerprint hardware
            
            # Call handover related
            "android.permission.ACCEPT_HANDOVER", # Continue call on another device

            # System Critical Permissions
            "android.permission.SYSTEM_ALERT_WINDOW", # Display over other apps (CRITICAL)
            "android.permission.WRITE_SETTINGS", # Modify system settings (CRITICAL)
            "android.permission.PACKAGE_USAGE_STATS", # Access app usage statistics (CRITICAL)
            "android.permission.REQUEST_INSTALL_PACKAGES", # Request package installation (CRITICAL)
            "android.permission.QUERY_ALL_PACKAGES", # Query all packages (CRITICAL)
            "android.permission.READ_LOGS", # Read system logs (CRITICAL)
            "android.permission.INSTALL_PACKAGES", # Install packages (CRITICAL)
            "android.permission.DELETE_PACKAGES", # Delete packages (CRITICAL)
            "android.permission.DUMP", # Retrieve system internal state (CRITICAL)
            "android.permission.READ_PRIVILEGED_PHONE_STATE", # Read privileged phone state (CRITICAL)
            "android.permission.MODIFY_PHONE_STATE", # Modify phone state (CRITICAL)
            "android.permission.WRITE_SECURE_SETTINGS", # Modify secure system settings (CRITICAL)
            "android.permission.MOUNT_UNMOUNT_FILESYSTEMS", # Mount/unmount filesystems (CRITICAL)
            "android.permission.MASTER_CLEAR", # Reset system to factory defaults (CRITICAL)
            "android.permission.FACTORY_RESET", # Perform factory reset (CRITICAL)
            "android.permission.REBOOT", # Reboot device (CRITICAL)
            
            # Root and System Level Permissions
            "android.permission.ROOT", # Root access (CRITICAL)
            "android.permission.MANAGE_USERS", # Manage users (CRITICAL)
            "android.permission.INTERACT_ACROSS_USERS", # Interact across users (CRITICAL)
            "android.permission.INTERACT_ACROSS_USERS_FULL", # Full cross-user interaction (CRITICAL)
            "android.permission.MANAGE_DEVICE_ADMINS", # Manage device administrators (CRITICAL)
            "android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS", # Manage profile/device owners (CRITICAL)
            "android.permission.OBSERVE_APP_USAGE", # Observe app usage (CRITICAL)
            "android.permission.UPDATE_APP_OPS_STATS", # Update app ops statistics (CRITICAL)
            "android.permission.MANAGE_APP_OPS_MODES", # Manage app operations (CRITICAL)
            
            # Network Critical Permissions
            "android.permission.CHANGE_NETWORK_STATE", # Change network state (CRITICAL)
            "android.permission.OVERRIDE_WIFI_CONFIG", # Modify Wi-Fi settings (CRITICAL)
            "android.permission.CONNECTIVITY_INTERNAL", # Internal networking (CRITICAL)
            "android.permission.NETWORK_STACK", # Network stack access (CRITICAL)
            "android.permission.NETWORK_SETTINGS", # Network settings (CRITICAL)
            "android.permission.NETWORK_SETUP_WIZARD", # Network setup wizard (CRITICAL)
            "android.permission.WRITE_APN_SETTINGS", # Modify APN settings (CRITICAL)
            
            # Security Critical Permissions
            "android.permission.MANAGE_ENCRYPTION", # Manage device encryption (CRITICAL)
            "android.permission.CONTROL_VPN", # Control VPN (CRITICAL)
            "android.permission.CONTROL_KEYGUARD", # Control keyguard (CRITICAL)
            "android.permission.CONTROL_SECURE_SETTINGS", # Control secure settings (CRITICAL)
            "android.permission.BIND_DEVICE_ADMIN", # Bind device admin (CRITICAL)
            "android.permission.BIND_ACCESSIBILITY_SERVICE", # Bind accessibility service (CRITICAL)
            "android.permission.BIND_INPUT_METHOD", # Bind input method (CRITICAL)
            "android.permission.BIND_VPN_SERVICE", # Bind VPN service (CRITICAL)
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", # Bind notification listener (CRITICAL)
            "android.permission.BIND_PRINT_SERVICE", # Bind print service (CRITICAL)
            "android.permission.BIND_DREAM_SERVICE", # Bind dream service (CRITICAL)
            "android.permission.BIND_WALLPAPER", # Bind wallpaper (CRITICAL)
            
            # Hardware Critical Permissions
            "android.permission.MANAGE_USB", # Manage USB (CRITICAL)
            "android.permission.ACCESS_PDB_STATE", # Access PDB state (CRITICAL)
            "android.permission.MODIFY_AUDIO_ROUTING", # Change audio routing (CRITICAL)
            "android.permission.CAPTURE_AUDIO_OUTPUT", # Capture audio output (CRITICAL)
            "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT", # Capture secure video output (CRITICAL)
            "android.permission.CONTROL_DISPLAY_BRIGHTNESS", # Control display brightness (CRITICAL)
            "android.permission.CONTROL_LOCATION_UPDATES", # Control location updates (CRITICAL)
            "android.permission.LOCATION_HARDWARE", # Location hardware access (CRITICAL)
            
            # Development and Debug Permissions
            "android.permission.SET_DEBUG_APP", # Set debug app (CRITICAL)
            "android.permission.SET_PROCESS_LIMIT", # Set process limit (CRITICAL)
            "android.permission.SET_ALWAYS_FINISH", # Set always finish (CRITICAL)
            "android.permission.SIGNAL_PERSISTENT_PROCESSES", # Signal persistent processes (CRITICAL)
            "android.permission.GET_APP_OPS_STATS", # Get app ops stats (CRITICAL)
            "android.permission.UPDATE_DEVICE_STATS", # Update device statistics (CRITICAL)
        ]

        for permission in self.apk.get_permissions():
            if permission in dangerous_permissions:
                self.vulnerabilities.append({
                    "type": "Dangerous Permission",
                    "details": f"App requests dangerous permission: {permission}",
                    "severity": "Medium",
                })

    def scan_exported_components(self) -> None:
        activities = self.apk.get_activities()
        services = self.apk.get_services()
        receivers = self.apk.get_receivers()

        for activity in activities:
            if self.is_component_exported("activity", activity):
                self.vulnerabilities.append({
                    "type": "Exported Component",
                    "details": f"Exported activity found: {activity}",
                    "severity": "High",
                })

        for service in services:
            if self.is_component_exported("service", service):
                self.vulnerabilities.append({
                    "type": "Exported Component",
                    "details": f"Exported service found: {service}",
                    "severity": "High",
                })

        for receiver in receivers:
            if self.is_component_exported("receiver", receiver):
                self.vulnerabilities.append({
                    "type": "Exported Component",
                    "details": f"Exported receiver found: {receiver}",
                    "severity": "High",
                })

    def scan_ssl_security(self) -> None:
        """
        Scans the APK for potential SSL/TLS misconfigurations or use of insecure HTTP protocols.
        """
        for method in self.analysis.get_methods():
            method_name = method.get_name()
            method_code = method.get_source()

            if method_code and ("HttpURLConnection" in method_code or "SSLSocket" in method_code):
                if "setHostnameVerifier" in method_code and "ALLOW_ALL_HOSTNAME_VERIFIER" in method_code:
                    self.vulnerabilities.append({
                        "type": "SSL Misconfiguration",
                        "details": f"Insecure Hostname Verifier detected in method {method_name}.",
                        "severity": "High",
                        "recommendation": "Avoid using 'ALLOW_ALL_HOSTNAME_VERIFIER' and implement proper hostname verification.",
                    })

                if "setDefaultSSLSocketFactory" in method_code and "TrustAllCertificates" in method_code:
                    self.vulnerabilities.append({
                        "type": "SSL Misconfiguration",
                        "details": f"Insecure SSL socket configuration in method {method_name}.",
                        "severity": "High",
                        "recommendation": "Do not disable SSL certificate validation; use a properly configured trust manager.",
                    })

                if "http://" in method_code:
                    self.vulnerabilities.append({
                        "type": "Insecure Communication",
                        "details": f"Insecure HTTP protocol detected in method {method_name}.",
                        "severity": "Medium",
                        "recommendation": "Use HTTPS to ensure secure communication.",
                    })

    def run_scan(self) -> Dict[str, Any]:
        print(f"Scanning APK: {self.apk_path}")
        self.scan_permissions()
        self.scan_exported_components()
        self.scan_ssl_security()
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        report: Dict[str, Any] = {
            "scan_time": datetime.now().isoformat(),
            "apk_info": {
                "file_name": os.path.basename(self.apk_path),
                "package_name": self.apk.get_package(),
                "version_name": self.apk.get_androidversion_name(),
                "version_code": self.apk.get_androidversion_code(),
            },
            "vulnerabilities": self.vulnerabilities,
        }
        return report


def display_graphs(json_file_path: str) -> None:
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        vulnerabilities = data.get("vulnerabilities", [])
        type_counts = {}
        severity_counts = {}
        for vuln in vulnerabilities:
            v_type = vuln.get("type", "Unknown")
            severity = vuln.get("severity", "Unknown")
            type_counts[v_type] = type_counts.get(v_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Plot Type Distribution
        plt.figure(figsize=(10, 5))
        plt.bar(type_counts.keys(), type_counts.values(), color='skyblue')
        plt.title('Distribution of Vulnerability Types')
        plt.xlabel('Vulnerability Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig("type_distribution.png")
        plt.close()
        
        # Plot Severity Distribution
        plt.figure(figsize=(7, 5))
        plt.pie(severity_counts.values(), labels=severity_counts.keys(), autopct='%1.1f%%',
                startangle=140, colors=['#ff9999','#66b3ff','#99ff99','#ffcc99'])
        plt.title('Distribution of Vulnerability Severities')
        plt.tight_layout()
        plt.savefig("severity_distribution.png")
        plt.close()
        
        print("Graphs saved as type_distribution.png and severity_distribution.png")
    except Exception as e:
        print(f"Error: {e}")


def main():
    print("APK Security Scanner")
    print("====================")
    
    # Get user input
    apk_path = input("Enter path to .apk file: ").strip()
    if not os.path.exists(apk_path):
        print(f"Error: APK file not found at {apk_path}")
        return

    report_name = input("Enter filename to save (e.g., report.json): ").strip()
    save_dir = input("Enter path to save report file: ").strip()

    if not os.path.exists(save_dir):
        print(f"Directory does not exist: {save_dir}")
        return

    # Construct full path for report
    report_path = os.path.join(save_dir, report_name)

    # Run the scanner
    scanner = APKScanner(apk_path)
    report = scanner.run_scan()

    # Save the report
    with open(report_path, "w") as json_file:
        json.dump(report, json_file, indent=4)

    print(f"Scan complete. Report saved to {report_path}")
    
    # Display vulnerability graphs
    display_option = input("Would you like to display vulnerability graphs? (y/n): ").strip().lower()
    if display_option == 'y':
        display_graphs(report_path)


if __name__ == "__main__":
    main()
