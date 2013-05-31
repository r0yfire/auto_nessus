#!/usr/bin/env python
'''
JoiNessus

Version 0.1.1

by Roy Firestein (roy@firestein.net)


Combine multiple Nessus scans into one.

'''


import os
import xml.dom.minidom
from optparse import OptionParser


parser = OptionParser()
parser.add_option("-f", "--first",  action="store", type="string", dest="first", help="First Nessus file to use")
parser.add_option("-d", "--dir",  action="store", type="string", dest="dir", help="Directory containing .nessus files")
parser.add_option("-o", "--output",  action="store", type="string", dest="output", help="output file name")
parser.add_option("-n", "--name",  action="store", type="string", default="combined scan", dest="name", help="New report name")
(menu, args) = parser.parse_args()


if menu.first and menu.dir and menu.output:
	files = []
	files.append(os.path.realpath(menu.first))
	dir_nessus = os.path.realpath(menu.dir)
	nessus_files = os.listdir(dir_nessus)
	scan_result = []
	counter = 0
	
	if nessus_files.__contains__(os.path.basename(files[0])):
		nessus_files.remove(os.path.basename(files[0]))
	for nes_file in nessus_files:
		files.append(os.path.join(dir_nessus, nes_file))
	
	for nes_file in files:
		nessus_xml = open(nes_file, 'r').read()
		if counter == 0:
			# first Nessus scan
			first_dom = xml.dom.minidom.parseString(nessus_xml)
			if menu.name:
				first_dom.getElementsByTagName('Report')[0].setAttribute('name', menu.name)
		else:
			try:
				dom = xml.dom.minidom.parseString(nessus_xml)
				test = dom.getElementsByTagName('ReportHost')
			except:
				# if no element "ReportHost", skip this
				print "Could not parse %s" %nes_file
				continue
			for host in dom.getElementsByTagName('ReportHost'):
				scan_result.append(host)
		counter=counter+1
	
	for node in scan_result:
		first_dom.getElementsByTagName('Report')[0].appendChild(node)
		
	fh = open(menu.output, 'w')
	first_dom.writexml(fh)
	fh.close()
else:
	parser.print_help()
	
