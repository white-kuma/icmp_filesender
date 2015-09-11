# coding:utf-8

#
# Send a file to remote by using ICMP (Root required)
#

import socket
import sys
import os.path
import struct

# supported icmp types
ECHO_REPLY = 0
ECHO = 8

# datasize(byte) / 1 packet
ICMP_DATASIZE = 32


# check whether ipaddr is IPv4 address
def isValidIPAddr(ipaddr):
	elems = ipaddr.split('.')

	if len(elems) != 4:
		return False
	
	for e in elems:
		if e.isdigit() == False:
			return False
		if not (0 <= int(e) <= 255):
			return False
	
	return True


# calc checksum
def calcChecksum(header):
	if len(header) % 2 == 1:
		header += b"\x00"
	
	checksum = 0
	for i in range(0, len(header), 2):
		checksum += (header[i] << 8) + header[i + 1]
	checksum = (checksum & 0xFFFF) + (checksum >> 16)
	checksum = 0xFFFF - checksum
	return struct.pack(">H", checksum)


# build ICMP Header
def buildICMPHeader(data, icmptype = ECHO_REPLY, identify = 0, seq = 0):
	if icmptype == ECHO_REPLY or icmptype == ECHO:
		b_type = struct.pack("B", icmptype)
		b_code = b"\x00"
		b_id = struct.pack(">H", identify)
		b_seq = struct.pack(">H", seq)
		b_data = data
		b_checksum = calcChecksum(b_type + b_code + b_id + b_seq + b_data)
		return b_type + b_code + b_checksum + b_id + b_seq + b_data
	else:
		return b""
		

# entry point
if __name__ == "__main__":
	# check num of args
	if len(sys.argv) != 3:
		print("usage: python3 {0} <dest_ipaddr> <filename>".format(sys.argv[0]))
		print("")
		print("This script sends <filename> to <dest_ipaddr> using by ICMP")
		exit(2)
	
	ipaddr = sys.argv[1]
	filename = sys.argv[2]
	
	# check args
	if not isValidIPAddr(ipaddr):
		print("Error: IP Address {0} is invalid format.".format(ipaddr))
		exit(1)
	if not os.path.exists(filename):
		print("Error: Filename {0} does not exist.".format(filename))
		exit(1)
	if not (os.path.getsize(filename) <= (ICMP_DATASIZE * 0xFFFE)):
		print("Error: Size of {0} is too large.".format(filename)) 
		exit(1)
		
	# create raw socket (root required) and send a file by using icmp
	seq_cnt = 0
	with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
		with open(filename, "rb") as f:
			while True:
				data = f.read(ICMP_DATASIZE)
				if len(data) == 0:
					# send end packet
					icmpheader = buildICMPHeader(data, identify = 1192, seq = 0xFFFF)
					sock.sendto(icmpheader, (ipaddr, 0))
					break
				
				icmpheader = buildICMPHeader(data, identify = 1192, seq = seq_cnt)
				sock.sendto(icmpheader, (ipaddr, 0))
				seq_cnt += 1
	
	exit(0)