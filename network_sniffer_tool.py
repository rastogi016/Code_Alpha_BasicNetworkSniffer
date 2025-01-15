#!/bin/python3


import socket
from datetime import datetime as dt

def sniffer_socket():
	"""
	Creates a raw socket to capture all traffic.
	"""
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	sniffer.bind(("0.0.0.0", 0)) # Binds to all network interfaces
	
	return sniffer

def analyze_packet(packet):
	"""
	Extract source, detination IPs and port from packet
	"""
	ip_header = packet[0:20] # TCP header is typically 20 bytes
	ip_protocol = packet[9]  # 9th byte holds the protocol (TCP, UDP, etc)
	
	source_ip = ".".join(map(str,ip_header[12:16]))
	destination_ip = ".".join(map(str, ip_header[16:20]))
	
	if ip_protocol == 6:  # TCP - 0x06
		print(f"TCP Packet | Source {source_ip} -> Destination {destination_ip}")
	elif ip_protocol == 17: # UDP - 0x11
		print(f"UDP Packet | Source {source_ip} -> Destination {destination_ip}")
	else:
		print(f"Other Protocol ({ip_protocol}) Packet | Source {source_ip} -> Destination {destination_ip}")

def sniffing():   # Starts the sniffer and captures packets
	
	sniffer = sniffer_socket()
	print("-"*70)
	print("[*] Network Sniffing is started. Capturing packets ....... \n")
	print("Start Time: ", str(dt.now()))
	print("-"*70)
	
	try:
		while True:
		# Receive a pakcet (65565 is the maximum size of a packet)
			packet, _ = sniffer.recvfrom(65565)
			analyze_packet(packet)
	except KeyboardInterrupt:
		print("\n[!] Sniffer Stopped by user")
		print("End Time: ", str(dt.now()))
	finally:
		sniffer.close()

if __name__=="__main__":
	sniffing()
	
