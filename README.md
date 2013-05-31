nessus_dispatch
===============

Nessus Dispatcher is a tool that automates and manages large VA scans with multiple Nessus scanners. It is especially useful for engagement with short scan windows, and/or large IP scope.


Dependecies
-----------

+ netaddr
+ python-nessus

Install all using pip:

	pip install netaddr nessus


Configuring Scanners
--------------------

Edit the script, and add scanners to the list at the top of the file.
It should look something like this:

	SERVERS = (
	     {"name": "scanner1", "url": "https://127.0.0.1:8834", "user": "admin", "pass": "password", "policy": "1"},
	     {"name": "scanner2", "url": "https://127.0.0.2:8834", "user": "admin", "pass": "password", "policy": "1"},
	)


Starting a scan
---------------

Create a text file with the IP ranges for the engagement. You can use ranges, single hosts and CIDR notation (like nmap). Make sure to have one entry per line. 
Once you have your targets and scanners configured, you can start the scan, like this:

	./nessus_dispatch.py -t targets.txt -n customer_name -v scan
	


Usage
-----

	./nessus_dispatch.py --help
	
	Usage: nessus_dispatch.py [options] scan | list | running
	
	Options:
	  -h, --help            show this help message and exit
	  -t TARGETS, --targets=TARGETS
	                        Targets file
	
	  Extra options:
	    -n NAME, --name=NAME
	                        File name
	    -d DIRECTORY, --dir=DIRECTORY
	                        Output directory
	    -g GROUP, --group=GROUP
	                        Group size of IPs to scan
	    -i INDEX, --index=INDEX
	                        Scan index starts from 0
	    -v, --verbose       Show extra information



auto_nessus
===========

Run large Nessus scans with a Home Feed.
The auto_nessus script chops the target IP ranges to groups of 16 addresses. Scans are saved locally, and can be joined together using the 'joinessus.py' script.


Dependecies
-----------

+ netaddr
+ python-nessus

Install all using pip:

	pip install netaddr nessus
  

Usage
-----

First, edit the script with the appropriate information:

+ targets file
+ output directory
+ project name
+ nessus server address
+ nessus server port
+ nessus user
+ nessus password


Then, enter IP addresses in CIDR notation into the targets file you specified in the step above.


Determine which policy you want to use by running:

	./auto_nessus.py --list
	

Start a scan using chosen policy ID

	./auto_nessus.py --scan ID
  




joinessus
=========

Join two or more nessus reports into one.


Usage
-----

  ./joinessus.py -f report_10.0.0.1-10.0.0.18_0.nessus -d ~/Desktop/scan -o single_report.nessus -n "Test Scan"
