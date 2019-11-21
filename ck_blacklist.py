from typing import List, Any

import urllib3
import csv
from scapy.all import *
from scapy.config import conf

conf.use_pcap = True
ips = []
str1 = ''
pcap = rdpcap("capture.cap")
link = "https://isc.sans.edu/block.txt"
mylines = []
iplist: List[Any]=[]
newblocklist=[]
newcaplist=[]
def fatch(link):
	http = urllib3.PoolManager()
	response = http.request('GET', link)
	data = response.data.decode('utf-8')
	assert isinstance(data, object)
	with open('data3.txt','w') as f:
		f.write(data)

def remove_sign():
	with open('data3.txt', 'r') as input_file:
		with open('data4.txt', 'w') as output_file:
			line: str
			for line in input_file:
				if (line[0] != "#"):
					output_file.write(line)
def blacklist():
	with open('data4.txt', 'r') as file:
		reader: object = csv.DictReader(file, delimiter='\t')
		for row in reader:
			iplist.append(row['Start'])
	return iplist

def remove_last_octet (n: object) -> object:
	result = []
	i = ""
	for row in n:
			i = '{}.'.format(row.rsplit('.', 1)[0])
			result.append(i)
	return result

def capture (pcap):
	for pkt in pcap:
		if (pkt.haslayer(IP)):
			str1 = str(pkt[IP].src)
			if str1 not in ips:
				ips.append(str1)
	return ips

def main():
	fatch(link)
	remove_sign()
	blacklist()
	capture(pcap)
	newblocklist = remove_last_octet(iplist)
	newcaplist = remove_last_octet(ips)
	newcaplist.append('89.248.174.')                # just to see the lambda work, append a blocked ip
	print('Black List IPs:      ',list(newblocklist))    # you can append any new block ip by x.y.z.
	print('Captured IPs:        ',list(newcaplist))
	print('Alert: Attacked By:  ', list(filter(lambda x: x in newcaplist,newblocklist)))

if __name__ == "__main__":
	main()


