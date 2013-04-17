auto_nessus
===========

Run large Nessus scans with a Home Feed.
The auto_nessus script chops the target IP ranges to groups of 16 addresses. Scans are saved locally, and can be joined together using the 'joinessus.py' script.


Dependecies
-----------

+ ipaddr
+ python-nessus

Install all using pip:

  pip install ipaddr python-nessus
  

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
