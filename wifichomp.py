#!/usr/bin/python

""" 
Name : WifiChomp
Author : Matt Lorentzen
Date : 10/02/15
Description:
Creates a sqlite3 database and uses scapy to monitor the air for probes. Writes these to the datatbase.
"""

import sqlite3
from scapy.all import *
import colours, sys


def setupdb():
	#create database with job name
	#create cursor to navigate the database and perform actions
	cur = db.cursor()

	# table to hold client probes
	cur.execute("""CREATE TABLE IF NOT EXISTS clientprobes(
			id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			clientmac VARCHAR(50),
			ssid VARCHAR(100),
			location VARCHAR(99),
			UNIQUE(clientmac, ssid)
			)	
	""")


def banner():
	banner="""
       _ ___ _     _                 
 _ _ _|_|  _|_|___| |_ ___ _____ ___ 
| | | | |  _| |  _|   | . |     | . |
|_____|_|_| |_|___|_|_|___|_|_|_|  _|
                                |_| 
"""
	return colours.yellowtxt(banner)


def pktH(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		if len(pkt) > 0:
			testcase = pkt.addr2 + '---' + pkt.info
			if testcase not in clientprobes:
				# add this to the table and the database
				clientprobes.add(testcase)
				print "New Client Probe: " + pkt.addr2 + ' ' + pkt.info
				[clientmac, ssid] = testcase.split('---')
				counter = 1
				if len(ssid) > 0:
					db.execute("INSERT OR IGNORE INTO clientprobes(clientmac, ssid, location) VALUES(?,?,?)", (clientmac, ssid, location))			
					db.commit()
				
				print colours.greentxt("\n---------------- Client Probes ----------------\n")
				for probe in clientprobes:
					[clientmac, ssid] = probe.split('---')
					if counter < 10 :
						print colours.redtxt(str(counter)) + '  : ' + colours.bluetxt(clientmac) + ' --> ' + colours.yellowtxt(ssid)
					else:
						print colours.redtxt(str(counter)) + ' : ' + colours.bluetxt(clientmac) + ' --> ' + colours.yellowtxt(ssid)
					counter = counter + 1
				print colours.greentxt("\n-----------------------------------------------\n")
			
	
total = len(sys.argv)

if total < 3:
	print banner()
	print "[!] Usage   : ./wifichomp.py <interface> <count>"
	print "[?] Example : ./wifichomp.py mon0 10000\n"
else:
	clientprobes = set()
	location = raw_input(colours.greentxt("Enter the location : "))
	db = sqlite3.connect('client_probes.db')
	# creates set to keep track of duplicates	
	print colours.bluetxt("Setting up DB structure")
	setupdb()
	loc = location.upper()
	print banner()
	print colours.yellowtxt("Starting Sniffing at the location : " + colours.redtxt(loc))
	sniff(iface=sys.argv[1], count=sys.argv[2], prn = pktH)
	db.close()
