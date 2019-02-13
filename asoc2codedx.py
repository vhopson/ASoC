#!/usr/bin/python
#####
#
#    Convert IBM Analysis System on Cloud to Code Dx
#
#####

##########
# Required libraries
##########
import sys
import argparse
import json
import requests
import ConfigParser
import xml.etree.ElementTree as ET
import asoc

#####
# Main Entry Point
#####
def main(args) :
	# create an ASoC object
	ibm = asoc.ASoC(transport = ini.get("ASOC", "transport"),
					addr = ini.get("ASOC", "addr"))
	
	# if an access token file is available, check to see if the token
	# is still usable
	try:
		token_filename = ini.get("ASOC", "accessTokenFile")
		access_token = ibm.getAccessToken(token_filename)
	except:
		access_token = None
		token_filename = None

	# if the access token is "None", then the token file does not exist,
	# or has timed out.  Determine alternate authorization strategy from the ini file.
	keyid = None
	keysec = None
	user = None
	password = None
	
	try:
		keyid = ini.get("ASOC", "keyId")
		keysec = ini.get("ASOC", "keySecret")
	except:
		pass
	
	try:
		user = ini.get("ASOC", "user")
		password = ini.get("ASOC", "password")
	except:
		pass
	
	# this must be performed early to allow the object to communicate with 
	# the IBM cloud server
	ibm.setAccessToken(keyid, keysec, user, password, token_filename)
	codedx_xml = ibm.collectFindings(ini.get("ASOC", "application"))
	
	# now that we have the findings, add the pieces needed to print out the
	# Code Dx XML file
	reportxml = ET.Element("report", { "date" : ibm.report_date } )
	reportxml.append(codedx_xml)
	tree = ET.ElementTree(reportxml)
	tree.write("codedx.xml", xml_declaration=True, encoding='utf-8', method='xml')


#####
# Environmental Setup
#####
parser = argparse.ArgumentParser()
parser.add_argument("--config",
	"-c",
	required=True,
	help="Configuration of servers to interrogate for finding transfers")
args = parser.parse_args()

# collect and pass in the .ini information specified from the command line
ini = ConfigParser.ConfigParser()
ini.read(args.config)

if __name__ == "__main__" :
	main(ini)

