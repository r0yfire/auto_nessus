#!/usr/bin/env python
'''
Nessus-0-Matic

Version: 3.0
12/5/2012


by Roy Firestein [roy**AT**firestein.net]


REQUIREMENTS:
You need to include the following libraries:
1. python-nessus
2. ipaddr


Tested with Nessus 5.

'''

import sys, os
import time
try:
	import ipaddr
except ImportError:
	print "Error:\nipaddr missing.\nInstall using: 'pip install ipaddr'\n"
	sys.exit(0)

try:
	import nessus
except ImportError:
	print "Error:\npython-nessus missing.\nInstall using: 'pip install nessus'\n"
	sys.exit(0)


class AutoNessus(nessus.NessusConnection):
	
	
	def __init__(self, username, password, url='https://localhost:8834', **kwargs):
		super(AutoNessus, self).__init__(username, password, url)
		self.raw_targets = []
		self.targets = []
		self.reports = []
		self.policies = []
		self.scan = None
		self.name = kwargs.get("name", "scan")
		self.output_dir = kwargs.get("output_dir", "./")
		self.group_size = kwargs.get("group_size", 16)
		self.verbose = kwargs.get("verbose", False)
		self.index_counter = kwargs.get("index_counter", 0)
	
	def start_scan(self, policy_id):
		if not len(self.targets) > 0:
			print "No Targets Found."
			return False
		
		while True:
			self.check_auth()
			
			### Create new sub scan
			group = self.targets[self.index_counter]
			self.print_yellow("[%s] Starting new scan against: %s to %s" %(self.index_counter, group[0], group[-1]))
			name = "%s_%s_%s_to_%s" %(self.name, self.index_counter, group[0], group[-1])
			self.scan = self.create_scan(policy_id, name, group)
			
			### Check if scan is still running
			while True:
				report = self.get_scan_report()
				if report:
					if self.verbose:
						print "[v] Scan status: %s" %(report.status)
					if report.status == "running":
						time.sleep(60)
					elif report.status == "completed":
						break
			
			### Save report
			self.save_report(self.scan.uuid, name)
			
			### Stuff
			self.increment_counter()
			if self.all_scans_are_finished():
				self.print_green("[*] Scan completed.")
				self.send_notification()
				break
		
		self.print_blue("[+] Finished scanning all targets!")
		self.print_blue("[+] Good day.")
		return True
	
	def check_auth(self, force=False):
		if not self._authenticated or force:
			while True:
				try:
					if self.verbose:
						print "Trying to authenticate."
					self._authenticate()
					if self._authenticated:
						break
				except Exception as err:
					if self.verbose:
						print "Authentication failed."
						print err
					pass
		return self._authenticated
	
	def get_reports(self):
		self.check_auth()
		while True:
			try:
				self.reports = self.list_reports()
				break
			except Exception as err:
				if self.verbose:
					print err
				self.check_auth(force=True)
		return self.reports
	
	def get_policies(self):
		self.check_auth()
		while True:
			try:
				self.policies = self.list_policies()
				break
			except Exception as err:
				if self.verbose:
					print err
				self.check_auth(force=True)
		return self.policies
	
	def parse_targets(self, targets_file):
		self.raw_targets = open(targets_file, 'r').readlines()
		for net in self.raw_targets:
			subnet = ipaddr.IPv4Network(net)
			v4list = [str(x) for x in subnet if x._version == 4]
			for chunk in self.chunks(v4list, self.group_size):
				self.targets.append(chunk)
	
	def save_report(self, scan_uuid, file_name):
		fname = "%s%s.nessus" %(self.output_dir, file_name)
		outfile = open(fname , 'w')
		self.check_auth()
		self.download_report(scan_uuid, outfile)
		outfile.close()
		
	def increment_counter(self):
		self.index_counter = self.index_counter + 1
		
	def all_scans_are_finished(self):
		if len(self.targets) == self.index_counter:
			return True
		return False
	
	def get_scan_report(self):
		reports = self.get_reports()
		for r in reports:
			if r.name == self.scan.uuid:
				return r
		return None
	
	def print_policies(self):
		policies = self.get_policies()
		print "ID\tPolicy name"
		for key in policies:
			print "%s\t%s" %(key.id, key.name)
		print
		
	def print_scans(self):
		reports = self.get_reports()
		print "Status\tUUID"
		for report in reports:
			print "%s\t%s" %(report.status, report.name)
		print
	
	def chunks(self, l, n):
		return [l[i:i+n] for i in range(0, len(l), n)]

	def send_notification(self):
		os.system("curl -s fireste.in/ping/nessusscan/")
		print "Notification sent."
	
	def print_blue(self, text):
		print '\033[94m' + "%s" %text + '\033[0m'
		
	def print_yellow(self, text):
		print '\033[93m' + "%s" %text + '\033[0m'
	
	def print_green(self, text):
		print '\033[92m' + "%s" %text + '\033[0m'
	
	
	
	
		
def main():
	"""
	
	Main
	
	"""
	print
	print "\tauto_nessus | Nessus Automation script"
	print

	from optparse import OptionParser, OptionGroup
	usage_text = "usage: %prog [options] list | scan"
	parser = OptionParser(usage_text)
	extra = OptionGroup(parser, "Extra options")
	parser.add_option("-t", "--targets",  action="store", type="string", dest="targets", help="Targets file", default="targets.txt")
	parser.add_option("-u", "--user",  action="store", type="string", dest="username", help="Nessus username", default="admin")
	parser.add_option("-w", "--pass",  action="store", type="string", dest="password", help="Nessus password")
	parser.add_option("-p", "--port",  action="store", type="string", dest="port", help="Nessus port", default="8834")
	parser.add_option("-s", "--server",  action="store", type="string", dest="server", help="Nessus host", default="localhost")
	extra.add_option("-n", "--name",  action="store", type="string", dest="name", help="File name", default="scan")
	extra.add_option("-d", "--dir",  action="store", type="string", dest="directory", help="Output directory", default="./")
	extra.add_option("-g", "--group",  action="store", type="int", dest="group", help="Group size of IPs to scan", default=16)
	extra.add_option("-i", "--index",  action="store", type="int", dest="index", help="Scan index starts from 0", default=0)
	extra.add_option("-v", "--verbose",  action="store_true", dest="verbose", help="Show extra information")
	parser.add_option_group(extra)
	(menu, args) = parser.parse_args()
	
	if len(args) < 1:
		parser.error("incorrect number of arguments")
	
	server = menu.server
	port = menu.port
	url = "https://%s:%s" %(server, port)
	scanner = AutoNessus(menu.username, menu.password, url)
	scanner.verbose = menu.verbose

	if len(args) >= 1:
		if args[0] == "list":
			scanner.print_policies()
		elif args[0] == "scan":
			if len(args) != 2:
				parser.print_usage()
			else:
				scanner.group_size = menu.group
				scanner.index_counter = menu.index
				scanner.name = menu.name
				scanner.output_dir = menu.directory
				scanner.parse_targets(menu.targets)
				policy_id = args[1]
				scanner.start_scan(policy_id)
				
		elif args[0] == "running":
			scanner.print_scans()
	else:
		parser.print_usage()

if __name__ == "__main__":
	main()
	
exit
