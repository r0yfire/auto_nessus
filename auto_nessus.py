#!/usr/bin/env python
'''
Nessus-0-Matic

v2.0 
29/1/2012


by Roy Firestein [roy@firestein.net]


REQUIREMENTS:
You need to include the following libraries:
1. python-nessus
2. ipaddr


Tested with Nessus 5.

'''


## EDIT THIS ##
infile = "targets.txt"
outdir = "./"

project_name = "testing"

server = "localhost"
port = "8834"
user = "admin"
passwd = "admin"
## STOP EDITING ##




import sys
import time
try:
	import ipaddr
except ImportError:
	print "Error:\nipaddr missing.\nInstall using: 'pip install ipaddr'\n"
	sys.exit(0)

try:
	import nessus
except ImportError:
	print "Error:\npython-nessus missing.\nInstall using: 'pip install python-nessus'\n"
	sys.exit(0)


nessuslist = []

print "\tauto_nessus | Nessus Automation script"

def run(policyid):

	netlist = open(infile, 'r').readlines()
	nessuslist = []

	for net in netlist:
		subnet = ipaddr.IPv4Network(net)
		v4list = [str(x) for x in subnet if x._version == 4]
		
		for chunk in chunks(v4list, 16):
			nessuslist.append(chunk)

	nes = nessus.NessusConnection(user , passwd)
	print "[+] Connected to Nessus server"
	print "[+] %d IP groups to scan" %(len(nessuslist))

	i=0
	for group in nessuslist:
		print "[*] Starting new scan against: %s to %s" %(group[0], group[-1])
		name = "%s_%s_%s_to_%s" %(project_name, i, group[0], group[-1])
		scan = nes.create_scan(policyid, name, group)
		while True:
			uuid = scan.uuid
			reports = nes.list_reports()
			report = None
			for r in reports:
				if r.name == uuid:
					report = r
					break
			if report.status == "running":
				time.sleep(60)
			elif report.status == "completed":
				break
		fname = outdir + name + ".nessus"
		outfile = open(fname , 'w')
		report = nes.download_report(scan.uuid, outfile)
		outfile.close()
		i=i+1
		#print "[*] Finished scanning tagets: %s to %s" %(group[0], group[-1])
	
	print "[+] Finished scanning all targets!"
	print "[+] Good day."



def get_policies():
	nes = nessus.NessusConnection(user , passwd)
	policies = nes.list_policies()
	print "ID\tPolicy name"
	for key in policies:
		print "%s\t%s" %(key.id, key.name)
	print

def get_scans():
	nes = nessus.NessusConnection(user , passwd)
	reports = nes.list_reports()
	print "Status\tUUIS"
	for report in reports:
		print "%s\t%s" %(report.status, report.name)

def chunks(l, n):
	return [l[i:i+n] for i in range(0, len(l), n)]

def usage():
	print "Usage: "
	print "%s --list" %(sys.argv[0])
	print "%s --scan policyID" %(sys.argv[0])
	print





if sys.argv.__len__() > 1:
	if sys.argv[1] == "--list":
		get_policies()
	elif sys.argv[1] == "--scan":
		if sys.argv.__len__() != 3:
			usage()
		else:
			run(sys.argv[2])
	elif sys.argv[1] == "--running":
		get_scans()
else:
	usage()
	
	
exit
