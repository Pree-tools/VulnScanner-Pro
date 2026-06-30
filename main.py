from banner import show_banner
from scanner import scan_target

show_banner()

target = input("Enter Target IP or Hostname: ")

print("\n========== Scan Types ==========")
print("1. Fast Scan")
print("2. Service Version Scan")
print("3. Custom Port Scan")
print("4. Operating System Detection")

choice = input("\nSelect Option: ")

scan_target(target, choice)