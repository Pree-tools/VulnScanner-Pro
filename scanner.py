import nmap
import time
import os
from colorama import Fore, init

from validator import resolve_target
from risk import get_risk
from banner_grabber import grab_banner

init(autoreset=True)

scanner = nmap.PortScanner(
    nmap_search_path=("E:\\NMAP\\nmap.exe",)
)


def scan_target(target, choice):

    resolved_ip = resolve_target(target)

    if resolved_ip is None:
        print(Fore.RED + "[-] Invalid Hostname or IP Address!")
        return

    print(Fore.CYAN + f"\nResolved Target : {resolved_ip}")

    target = resolved_ip

    # Scan Types
    if choice == "1":
        arguments = "-F"

    elif choice == "2":
        arguments = "-sV"

    elif choice == "3":
        ports = input("Enter Port Range (Example: 1-1000): ")
        arguments = f"-p {ports}"

    elif choice == "4":
        arguments = "-O"

    else:
        print(Fore.RED + "[-] Invalid Choice!")
        return

    start = time.time()

    print(Fore.CYAN + "\n" + "=" * 90)
    print(Fore.YELLOW + f"Scanning Target : {target}")
    print(Fore.CYAN + "=" * 90)

    try:
        scanner.scan(hosts=target, arguments=arguments)

    except Exception as e:
        print(Fore.RED + f"Scan Failed: {e}")
        return

    os.makedirs("reports", exist_ok=True)

    report_path = os.path.join("reports", "scan_report.txt")

    with open(report_path, "w") as report:

        report.write("=" * 90 + "\n")
        report.write("VULNSCANNER PRO REPORT\n")
        report.write("=" * 90 + "\n\n")

        report.write(f"Target : {target}\n")
        report.write(f"Scan Type : {arguments}\n\n")

        for host in scanner.all_hosts():

            print(Fore.GREEN + f"\nHost : {host}")
            print(Fore.WHITE + f"Status : {scanner[host].state()}")

            report.write(f"Host : {host}\n")
            report.write(f"Status : {scanner[host].state()}\n\n")

            # OS Detection
            if choice == "4":

                print(Fore.YELLOW + "\nOperating System")

                report.write("Operating System\n")

                if "osmatch" in scanner[host] and scanner[host]["osmatch"]:

                    for osmatch in scanner[host]["osmatch"]:
                        print(Fore.GREEN + f"- {osmatch['name']}")
                        report.write(f"- {osmatch['name']}\n")

                else:
                    print(Fore.RED + "OS Detection Failed")
                    report.write("OS Detection Failed\n")

                report.write("\n")

            for protocol in scanner[host].all_protocols():

                print(Fore.MAGENTA + f"\nProtocol : {protocol}")
                report.write(f"\nProtocol : {protocol}\n")

                ports = sorted(scanner[host][protocol].keys())

                header = (
                    f"{'PORT':<8}"
                    f"{'SERVICE':<18}"
                    f"{'STATE':<10}"
                    f"{'RISK':<10}"
                    f"{'VERSION':<25}"
                    f"{'BANNER'}"
                )

                print(Fore.CYAN + header)
                print("-" * 90)

                report.write(header + "\n")
                report.write("-" * 90 + "\n")

                for port in ports:

                    service = scanner[host][protocol][port]["name"]
                    state = scanner[host][protocol][port]["state"]

                    product = scanner[host][protocol][port].get("product", "")
                    version = scanner[host][protocol][port].get("version", "")

                    version_info = f"{product} {version}".strip()

                    risk = get_risk(port)

                    # Banner Grabbing
                    if state == "open":
                        banner = grab_banner(target, port)
                    else:
                        banner = "-"

                    line = (
                        f"{port:<8}"
                        f"{service:<18}"
                        f"{state:<10}"
                        f"{risk:<10}"
                        f"{version_info:<25}"
                        f"{banner}"
                    )

                    if risk == "HIGH":
                        color = Fore.RED
                    elif risk == "MEDIUM":
                        color = Fore.YELLOW
                    else:
                        color = Fore.GREEN

                    print(color + line)
                    report.write(line + "\n")

                report.write("\n")

    end = time.time()

    print(Fore.CYAN + "\n" + "=" * 90)
    print(Fore.YELLOW + f"Scan Completed in {end - start:.2f} seconds")
    print(Fore.GREEN + f"Report saved at:\n{os.path.abspath(report_path)}")
    print(Fore.CYAN + "=" * 90)