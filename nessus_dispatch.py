#!/usr/bin/env python
'''

##
###
### Nessus Dispatcher
###
##

Version: 1.0 RC1
Date: 22/5/2012
Author: Roy Firestein [roy**AT**firestein.net]


REQUIREMENTS:
You need to include the following libraries:
1. python-nessus
2. netaddr


Tested with Nessus 5.

'''


SERVERS = (
    #
    # Insert Nessus scanners here
    #
    # Entry Example:
    #{"name": "scanner1", "url": "https://127.0.0.1:8834", "user": "admin", "pass": "password", "policy": "1"},
)





from threading import Thread
import signal
import time
import sys
import os
import re
import random
try:
    import netaddr
except ImportError:
    print "Error:\nipaddr missing.\nInstall using: 'pip install netaddr'\n"
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
            return False
        
        ### start new can
        self.check_auth()
        group = self.targets
        name = "%s_%s_to_%s" %(self.name, group[0], group[-1])
        while True:
            try:
                self.scan = self.create_scan(policy_id, name, group)
                break
            except:
                self.check_auth(force=True)
        
        ### Loop until scan completes
        while True:
            report = self.get_scan_report()
            if report:
                if report.status == "running":
                    time.sleep(60)
                elif report.status == "completed":
                    break
        
        ### Save report
        self.save_report(self.scan.uuid, name)
        return
    
    def check_auth(self, force=False):
        if not self._authenticated or force:
            while True:
                try:
                    self._authenticate()
                    if self._authenticated:
                        break
                except:
                    pass
        return self._authenticated
    
    def get_reports(self):
        while True:
            try:
                self.reports = self.list_reports()
                break
            except:
                self.check_auth(force=True)
        return self.reports
    
    def get_policies(self):
        while True:
            try:
                self.policies = self.list_policies()
                break
            except:
                self.check_auth(force=True)
        return self.policies
    
    def save_report(self, scan_uuid, file_name):
        while True:
            try:
                fname = "%s%s.nessus" %(self.output_dir, file_name)
                outfile = open(fname , 'w')
                self.check_auth()
                self.download_report(scan_uuid, outfile)
                outfile.close()
                break
            except:
                pass
    
    def get_scan_report(self):
        reports = self.get_reports()
        for r in reports:
            if r.name == self.scan.uuid:
                return r
        return None


class ScanThread(Thread):
    def __init__(self, user, passwd, url, policy, **kwargs):
        super(ScanThread, self).__init__()
        self.url = url
        self.policy_id = policy
        self.group_size = kwargs.get("project_name", 16)
        self.index_counter = kwargs.get("index_counter", 0)
        self.project_name = kwargs.get("project_name", "scan")
        self.output_dir = kwargs.get("output_dir", "./")
        self.targets = kwargs.get("targets", [])
        self.name = kwargs.get("name", "")
        self.scanner = AutoNessus(user, passwd, url)

    def run(self):
        self.scanner.group_size = self.group_size
        self.scanner.index_counter = self.index_counter
        self.scanner.name = self.project_name
        self.scanner.output_dir = self.output_dir
        self.scanner.targets = self.targets
        self.scanner.start_scan(self.policy_id)
#         time.sleep(random.choice([20,25,10,30,15]))


class NessusDispatcher(object):
    
    def __init__(self, **kwargs):
        self.SERVERS = SERVERS
        self.raw_targets = []
        self.targets = []
        self.project_name = kwargs.get("project_name", "scan")
        self.group_size = kwargs.get("group_size", 16)
        self.index_counter = kwargs.get("index", 0)
        self.output_dir = kwargs.get("output_dir", "./")
        self.verbose = kwargs.get("verbose", False)
        self.sleep_time = kwargs.get("sleep", 60)
        self.threads = []
        self.free_scanners = list(self.SERVERS)
        self.busy_scanners = []
        
    
    def start_scans(self):
        if not len(self.targets) > 0:
            print "No targets to scan."
            sys.exit(1)
        
        self.print_blue("[+] New scan initiated.")
        self.print_blue("[+] %s groups, each has %s IPs (%s total addresses)" %(len(self.targets), self.group_size, (len(self.targets)*self.group_size)))
        self.print_blue("[+] %s scanners available" %(len(self.SERVERS)))
        while True:
            
            # Exit if all threads are done and no more targets to scan
            if self.all_scans_are_finished():
                if self.alive_count() == 0:
                    self.print_green("[+] All scans finished.")
                    self.print_green("[+] Buy me a beer?")
                    self.send_notification()
                    break
            
            # Launch new thread for each available scanners
            if self.alive_count() != len(self.SERVERS) and not self.all_scans_are_finished():
                while len(self.free_scanners) > 0:
                    scanner = self.free_scanners.pop(random.choice(range(0,len(self.free_scanners))))
                    thread = ScanThread(scanner['user'], scanner['pass'], scanner['url'], scanner['policy'], name=scanner['name'])
                    if thread.isAlive() is False and not self.all_scans_are_finished():
                        group = self.targets[self.index_counter]
                        self.print_yellow("[%s] Starting new scan against %s to %s (%s)" %(self.index_counter, group[0], group[-1], scanner['name']))
                        # set parameters
                        thread.group_size = self.group_size
                        thread.index_counter = 0 ## Always zero
                        thread.project_name = "%s_%s" %(self.project_name, self.index_counter) ## Important, so file names are numbered!!
                        thread.output_dir = self.output_dir
                        thread.targets = group
                        # Start new scan
                        thread.start()
                        self.threads.append(thread)
                        self.busy_scanners.append(scanner)
                        self.increment_counter()
                    else:
                        self.free_scanners.append(scanner)
                        break
            time.sleep(5)
        return True
    
    def print_all_policies(self):
        self.threads = [ ScanThread(scanner['user'], scanner['pass'], scanner['url'], scanner['policy'], name=scanner['name']) for scanner in self.free_scanners ]
        for thread in self.threads:
            policies = thread.scanner.get_policies()
            print "Policies on %s" %(thread.name)
            print "ID\tPolicy name"
            for key in policies:
                print "%s\t%s" %(key.id, key.name)
            print
            
    def print_all_scans(self):
        self.threads = [ ScanThread(scanner['user'], scanner['pass'], scanner['url'], scanner['policy'], name=scanner['name']) for scanner in self.free_scanners ]
        running = 0
        for thread in self.threads:
            reports = thread.scanner.get_reports()
            print "Scans on %s" %(thread.name)
            print "Status\tUUID"
            for report in reports:
                if report.status == "running":
                    running = running+1
                    print "%s\t%s" %(report.status, report.name)
            print
        self.print_green("%s total running scans" %running)
        print
    
    def parse_targets(self, targets_file):
        self.raw_targets = open(targets_file, 'r').readlines()
        re_range = re.compile('^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3})$')
        re_net = re.compile('^(?P<net>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$')
        re_single = re.compile('^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
        ip_list = []
        ''' detect if IP is a range, network or single host '''
        for line in self.raw_targets:
            line = line.strip()
            if re_net.match(line):
                # Network
                network = netaddr.IPNetwork(line)
                v4list = [str(x) for x in network if x.version == 4]
                for ip in v4list:
                    ip_list.append(ip)
            elif re_single.match(line):
                # Single IP
                ip_list.append(line)
            elif re_range.match(line):
                # IP range
                iprange = netaddr.iter_nmap_range(line)
                for ip in iprange:
                    ip = str(ip)
                    ip_list.append(ip)
        # Break into specified groups size
        self.targets = [ chunk for chunk in self.chunks(ip_list, self.group_size) ]
        if len(self.targets) > 0:
            if self.verbose:
                self.print_blue("[+] Targets loaded successfully.")
        else:
            print "[+] Error loading targets."
            sys.exit(1)
    
    def increment_counter(self):
        self.index_counter = self.index_counter + 1
    
    def all_scans_are_finished(self):
        if len(self.targets) == self.index_counter:
            return True
        return False
    
    def chunks(self, l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]
    
    def alive_count(self):
        if len(self.threads) > 0:
            alive = []
            for thread in self.threads:
                if thread.isAlive():
                    alive.append(1)
                else:
                    alive.append(0)
                    url = thread.url
                    self.threads.remove(thread)
                    thread.join()
                    for scanner in self.busy_scanners:
                        if scanner['url'] == url:
                            self.busy_scanners.remove(scanner)
                            self.free_scanners.append(scanner)
                            if self.verbose:
                                print "[v] %s is finished" %scanner['name']
            return reduce(lambda a,b : a + b, alive)
        return 0
    
    def terminate(self, signal, frame):
        print "\nWaiting for current scans to finish..."
        print "This might take a while."
        self.verbose = True
        self.index_counter = len(self.targets)
    
    def send_notification(self):
        # Can insert email or SMS notification code here
        print
    
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
    print "\tNessus Dispatcher"
    print
    
    from optparse import OptionParser, OptionGroup
    usage_text = "usage: %prog [options] scan | list | running"
    parser = OptionParser(usage_text)
    extra = OptionGroup(parser, "Extra options")
    parser.add_option("-t", "--targets",  action="store", type="string", dest="targets", help="Targets file", default="targets.txt")
    extra.add_option("-n", "--name",  action="store", type="string", dest="name", help="File name", default="scan")
    extra.add_option("-d", "--dir",  action="store", type="string", dest="directory", help="Output directory", default="./")
    extra.add_option("-g", "--group",  action="store", type="int", dest="group", help="Group size of IPs to scan", default=16)
    extra.add_option("-i", "--index",  action="store", type="int", dest="index", help="Scan index starts from 0", default=0)
    extra.add_option("-v", "--verbose",  action="store_true", dest="verbose", help="Show extra information")
    parser.add_option_group(extra)
    (menu, args) = parser.parse_args()
    
    if len(args) < 1:
        parser.error("incorrect number of arguments")
    
    # Initialize scanner object
    dispatch = NessusDispatcher()
    dispatch.verbose = menu.verbose
    
    # Catch Ctrl-C
    signal.signal(signal.SIGINT, dispatch.terminate)
    
    # Determine what to do
    if len(args) >= 1:
        if args[0] == "list":
            dispatch.print_all_policies()
        elif args[0] == "scan":
            dispatch.group_size = menu.group
            dispatch.index_counter = menu.index
            dispatch.output_dir = menu.directory
            dispatch.project_name = menu.name
            dispatch.parse_targets(menu.targets)
            dispatch.start_scans()
        elif args[0] == "running":
            dispatch.print_all_scans()
    else:
        parser.print_usage()

if __name__ == "__main__":
    main()
    