from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Initialize list of devices
    devices = []

    # Parse the response
    for sent, received in result:
        # For each response, get IP and MAC Address
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Display the result
    print("\nDevices found:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")
    print("-" * 40)

def main():
    # Team and developer info
    team_name = "The Universal Linux Society"
    developer_name = "Rayyan Afridi"

    print(f"Network Scanner by {team_name}")
    print(f"Developed by {developer_name}\n")

    while True:
        print("Choose an option:")
        print("1: Network Scanner")
        print("0: Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            ip_range = input("Enter IP range (e.g., 192.168.1.1/24): ")
            print("\nScanning the network, please wait...\n")
            scan_network(ip_range)
        elif choice == "0":
            print("Exiting the program.")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
