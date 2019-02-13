#####
# IBM Application Security on Cloud (ASoC) Object
#
#####
from __future__ import print_function
import sys
import requests
import json
import xml.etree.ElementTree as ET
import datetime
import dateutil.parser as dup
from dateutil.tz import tzlocal
import re
import posixpath

#####
# Class Object for ASoC Communication
#
#####
class ASoC :
	#####
	# Some ASoC constants (settable)
	#####
	top = 1000           # maximum number of finding records to return in each call
	timeRemaining = 300  # number of seconds that must remain on the access key

	#####
	# Constructor
	#
	# This initializes:
	#   self.port = port for communication
	#	self.transport = used for establishing whether or not to init SSL
	#	self.addr = the raw ASoC address for contacting
	#####
	def __init__(self, transport, addr, port = "") :	
		# translate the transport to a port number to save in the object
		if port == "" :
			if transport.lower() == "http" :
				self.port = 80
			else :
				self.port = 443
		else :
			self.port = port
			
		# set up contact address and transport
		self.addr = addr
		self.transport = transport.lower()
		self.url = self.transport + "://" + self.addr + ":" + str(self.port) + "/api/V2"
		
		print("ASoC Object Constructor Called")
		print("    |- transport: " + transport.lower())
		print("    |- IBM Cloud address: " + addr)
		print("    |- setting cloud port to " + str(self.port))
		print("    |- base URL " + self.url)
		
		# set a flag to indicate this object has not created an access token as yet
		self.token_valid = False
		self.access_token = None
		
		self.report_date = None		# this becomes valid after acquisition of findings
		
	#####
	# Get Access Token
	#
	# This routine attempts to get the access token specified in the incoming filename.
	# Any errors do not set the internal access token, and this routine returns a None.
	# 
	# If a file exists, then the values inside are checked.  There must be more than
	# self.timeRemaining for the access token to be used.
	#
	# File doesn't exist : return None
	# File exists, but contents are wrong : return None
	# Contents have key, but time is less than self.timeRemaining : return None
	# Good file, good key, sufficient time left : return the access token, and set
	#   its value into this object for use.
	#
	#####
	def getAccessToken(self, filename) :
		if self.token_valid == True :
			return self.access_token

		# attempt to open and load the JSON file for the access token
		retval = None
		try:
			with open(filename, "r") as fp :
				token = json.load(fp)
			
			token_date = token["Expire"]
			self.access_token = token["Token"]
			
			# check the expiry to be sure it is more than self.timeRemaining
			expiry = dup.parse(token_date) - datetime.datetime.now(tzlocal())
			if expiry.total_seconds() > self.timeRemaining :
				# good expiration on good key
				self.token_valid = True
				retval = self.access_token
				print("    |- [getAccessToken] - good token received with timeout in " + str(expiry.total_seconds()) + " seconds")
			else:
				print("    |- [getAccessToken] - good token file, but token has expired.")
	
		except Exception as ex :
			print("    |- [getAccessToken] no valid file containing token")
		
		return retval
	
	#####
	# Acquire Access Token from Cloud
	#
	# We can use either KeyId, and KeySecret; or username and password to create
	# an access token.  Check for the strategy we will use, and create the token
	# needed by accessing the IBM ASoC server.
	#
	# If both are specified, we use the keyid/keypass in preference
	#
	#####
	def setAccessToken(self, keyid = None, keypass = None, user = None, password = None, filename = None) :
	
		# check to see if an access token is already in place.  If so,
		# simply return
		if self.token_valid == True :
			return
		
		# check to be sure we are not getting a bad call
		if keyid == None and user == None :
			print("\n*****Error: no server access strategy selected.\n")
			return
		
		# check to see which strategy we will be using for access
		if keyid != None :
			# we will be using Key ID/Key Password
			self.keyid = keyid
			self.keypass = keypass
			self.user = None
			self.password = None
			self.key_strategy = True
		else :
			# this uses the username/password strategy
			self.keyid = None
			self.keypass = None
			self.user = user
			self.password = password
			self.key_strategy = False
		
		# log what we are using
		print("    |- Using Key access strategy? ", self.key_strategy)
		
		# prepare the connection JSON header information.  Used for either endpoint
		hdr = { "Content-Type" : "application/json",
				"Accept" : "application/json" }
		
		# figure out which endpoint we need to get the token from
		if self.key_strategy == True :
			endpoint = self.url + "/Account/ApiKeyLogin"
			payload = { "KeyId" : self.keyid, "KeySecret" : self.keypass }
		else :
			endpoint = self.url + "/Account/IBMIdLogin"
			payload = { "Username" : self.user, "Password" : self.password }
		
		# reach out to the server for an access token
		resp = requests.post(endpoint, headers = hdr, json = payload)
		print("    |- request status: " + str(resp.status_code))
		
		# if this was successful, grab the token out of the message.  This
		# message is written in its entirety to the filename passed to this
		# function if possible.
		if resp.status_code == requests.codes.ok :
			ret = resp.json()
			self.access_token = ret["Token"]
			print("    |- Using access token: " + self.access_token)
			self.token_valid = True
			if filename != None :
				with open(filename, "w") as ofp :
					json.dump(ret, ofp)
	
	#####
	# Collect Scan ID
	# 
	# Collect all scans of the given application.  We grab the ID from it to return
	#
	#####
	def collectScanId(self, application) :
		# be sure the Access Token is valid
		if self.token_valid == False :
			return None
		
		# set the header for this call
		hdr = { "Accept" : "application/json", "Authorization" : "Bearer " + self.access_token }
		
		# create the call
		endpoint = self.url + "/Scans"
		resp = requests.get(endpoint, headers = hdr)
		if resp.status_code != requests.codes.ok :
			print("    |- [collectScanId] bad return on request - " + str(resp.status_code))
			return None
		
		# collect the scan information and look for our application
		scans = resp.json()
		scan_loc = len(scans)
		
		id = ""
		for scan in scans :
			if scan["Name"] == application :
				id = scan["Id"]
				print("    |- [collectScanId] found Id " + id)
				self.report_date = scan["CreatedAt"]
				break
		
		return id
		
	#####
	# Collect Findings for the Project
	#
	# Query the ASoC server for the findings that will be written to Code Dx
	# The return value of this call is the root of the Code Dx tree "findings".
	# Findings from the most recent scan of the application is used to capture
	# results.
	#
	# Mapping:
	#    ASoC        Code Dx               Notes
	# ----------  -------------  -----------------------------------
	#  Severity     severity      Translated through a static table "severity_conversion"
	#    Cwe           cwe
	#
	#####
	severity_conversion = {
		"High" : "high",
		"Medium" : "medium",
		"Low" : "low",
		"Informational" : "info" }
		
	def collectFindings(self, application) :
		scan_id = self.collectScanId(application)
		
		# set the header for this call
		hdr = { "Accept" : "application/json", "Authorization" : "Bearer " + self.access_token }
		
		# iterate over all of the available findings
		iter_count = 0
		incoming_findings = []
		
		while True :
			# get all of the issues related to this particular scan
			endpoint  = self.url + "/Scans/" + scan_id
			endpoint += "/Issues?$top=" + str(self.top) + "&$skip=" + str(len(incoming_findings))
			print("    |- Using endpoint \"" + endpoint + "\"")
			resp = requests.get(endpoint, headers = hdr)
			if resp.status_code != requests.codes.ok :
				print("    |- [collectFindings] bad return on request - " + str(resp.status_code))
				return None
			
			# collect the findings
			iter_count += 1
			new_findings = resp.json()
			new_findings_count = len(new_findings)
			incoming_findings += new_findings
			
			# check to see if we have collected all of the records.  If the incoming
			# finding count is less than the number we are requested, we are done
			if new_findings_count < self.top :
				break
			
			
		# finding list is complete
		print("    |- [collectFindings] collected: " + str(len(incoming_findings)))
		print("    |- [collectFindings] iterations: " + str(iter_count))
		
		# begin formatting the findings into the Code Dx XML
		findings = ET.Element("findings")
		
		# now go through the findings and create records
		for item in incoming_findings :
			finding = ET.SubElement(findings, "finding", 
									{ "severity" : self.severity_conversion[item["Severity"]] })
			ET.SubElement(finding, "cwe", { "id" : str(item["Cwe"]) })
			
			# prepare the tool name dictionary for the attributes
			tool_attrib = { "name" : "IBM ASoC", 
							"category" : item["IssueTypeId"],
							"code" : "" }
			ET.SubElement(finding, "tool", tool_attrib)
			
			# prepare the location information
			ibm_loc = re.search(r"\((.*):(\d+)\)", item["Location"])
			if ibm_loc != None :
				ibm_pathname = "android/" + ibm_loc.group(1).replace("\\", "/")
				ibm_lineno = str(ibm_loc.group(2))
			else:
				ibm_pathname = "Not Available"
				ibm_lineno = "1"
				
			loc_attr = { "type" : "file", "path" : ibm_pathname }
			location = ET.SubElement(finding, "location", loc_attr)
			lineno_attrib = { "start" : ibm_lineno, "end" : ibm_lineno }
			ET.SubElement(location, "line", lineno_attrib)
			
			# this is a placeholder
			column_attrib = { "start" : "1", "end" : "1" }
			ET.SubElement(location, "column", column_attrib)
			
			# a placeholder for the description
			desc = ET.SubElement(finding, "description", { "format" : "plain-text" })
			desc.text = item["IssueType"] + "\nIssue ID: " + item["Id"]
			
		# return the list of findings to the caller
		return findings
		

		
	
	
	
	