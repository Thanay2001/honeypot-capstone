#!/usr/bin/python

# DCEPT
# James Bettke
# Dell SecureWorks 2016

import GenerationServer
from Cracker import cracker
import pyshark
import os
import sys
import socket 

import logging
from logging import Logger
import ConfigParser
from ConfigReader import config
from ConfigReader import ConfigError

import pyshark
import pyiface
import alert

import urllib
import urllib2
import socket

# Globals
genServer = None

class DceptError(Exception):
	def __init__(self, message=""):
		Exception.__init__(self,message)

def kerbsniff(interface, username, domain, realm):

	logging.info("kerbsniff: Looking for %s\%s on %s" % (domain,username,interface))
	
	filtered_cap = pyshark.LiveCapture(interface, bpf_filter='tcp port 88')
	packet_iterator = filtered_cap.sniff_continuously
	
	# Loop infinitely over packets if in continuous mode
	for packet in packet_iterator():

		kp = None
		honeyHit = False

		try:
			kp = packet['kerberos']
			honeyHit = kerb_handler(kp, domain, username)
		except KeyError:
			pass

		if honeyHit:
			if config.master_node:
				notifyMaster(username, domain, "MATCHED_ASREQ")
			else:
				honeytokenHit(genServer, username)


def notifyMaster(username, domain, eventType):
    url = 'http://%s/notify' % (config.master_node)
    values = {
        'u': username,
        'd': domain,
        't': eventType
    }
    data = urllib.urlencode(values)

    try:
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req, timeout=30)
    except (urllib2.URLError, socket.timeout) as e:
        message = "DCEPT slave failed to communicate with master node '%s'" % (config.master_node)
        logging.error(message)
        alert.sendAlert(message)
        return False
    return True

def honeytokenHit(genServer, username):
    record = genServer.findUser(username)
    if record:
        message = "[RED ALERT] Honeytoken for %s\\%s was used from %s on %s" % (
            record[2], record[3], record[4], record[0].split(".")[0]
        )
    else:
        message = "[RED ALERT] Honeytoken account %s was used" % username

    print "\x1b[91m" + message + "\x1b[0m"
    logging.critical(message)
    alert.sendAlert(message)

def passwordHit(genServer, password):

	if password:
		record = genServer.findPass(password)
		message = "[RED ALERT] Honeytoken for %s\\%s '%s' was stolen from %s on %s" % \
			(record[1],record[2], record[4], record[3], record[0].split(" ")[0] )
		#print "\x1b[91m" + message + "\x1b[0m"
		print "\x1b[91m" + "[RED ALERT]" + "\x1b[0m"
		logging.critical(message)			
		alert.sendAlert(message)


# Parse Kerberos packet and return the encrypted timestamp only if we detected 
# honeytoken usage (honey domain\username)
def kerb_handler(kp, domain, username):
    kerbName = None
    realm = None

    try:
        msg_type = str(kp.msg_type).strip()
    except AttributeError:
        logging.debug("Ignoring kerberos packet - no msg_type")
        return False

    if msg_type != "10":
        logging.debug("Ignoring kerberos packet - Not kerb-as-req")
        return False

    for attr in ["CNameString", "cname_string", "name_string", "kerberosstring", "cnamestring"]:
        try:
            value = getattr(kp, attr)
            if value is not None and str(value).strip() != "":
                sval = str(value).strip()
                if sval.lower() != "none" and not sval.isdigit() and sval != "cname":
                    kerbName = sval
                    break
        except AttributeError:
            pass

    try:
        realm = str(kp.realm).strip()
    except AttributeError:
        logging.debug("Could not extract realm from kerberos packet. Skipping.")
        return False

    if kerbName is None:
        logging.debug("Could not extract username from kerberos packet. Skipping.")
        return False

    logging.info("kerb-as-req for domain user %s\\%s" % (realm, kerbName))

    if kerbName.lower() == username.lower() and config.realm.lower() in realm.lower():
        logging.critical("Honeytoken Kerberos authentication observed for %s\\%s" % (realm, kerbName))
        return True

    logging.debug("Ignoring kerb-as-req for '%s\\%s'" % (realm, kerbName))
    return False



def testInterface(interface):
	try:
		iface = pyiface.Interface(name=interface)
		if iface.flags == iface.flags | pyiface.IFF_UP:
			return True
	except IOError as e:
		if e.errno == 19: # No such device
			print "Bad interface. No such device '%s'" % (interface)
	return False

def main():
	banner = """
	  _____   _____ ______ _____ _______ 
	 |  __ \ / ____|  ____|  __ |__   __|
	 | |  | | |    | |__  | |__) | | |   
	 | |  | | |    |  __| |  ___/  | |   
	 | |__| | |____| |____| |      | |   
	 |_____/ \_____|______|_|      |_|
"""
 
	print banner
	
	try:
		# Read the configuration file
		config.load("/opt/dcept/dcept.cfg")
	except (ConfigParser.Error, ConfigError) as e:
		logging.error(e)
		raise DceptError()
	
	# Server roles for multi-server topology
	if not config.master_node:
		logging.info('Server configured as master node')
	else:
		logging.info('Server configured as slave node')

		# Test Connection to master node

	# Sanity check - Check if the interface is up
	if not testInterface(config.interface):
		logging.error("Unable to listen on '%s'. Is the interface up?" % (config.interface))
		raise DceptError()

	logging.info('Starting DCEPT...')

	# Only master node should run the generation server and cracker 
	if not config.master_node: # (Master Node)

		# Spawn and start the password generation server
		try:
			global genServer 
			genServer = GenerationServer.GenerationServer(config.honeytoken_host, config.honeytoken_port)
		except socket.error as e:
			logging.error(e)
			logging.error("Failed to bind honeytoken HTTP server to address %s on port %s" % (config.honeytoken_host, config.honeytoken_port))
			raise DceptError()

		# Initialize the cracker
		cracker.start(genServer)

	else: # (Slave Node)
		# Test sending notifications to the master node
		logging.info("Testing connection to master node '%s'" % (config.master_node))
		if not notifyMaster('u', 'd', 't'):
			raise DceptError()

	# Start the sniffer (Both master and slave)
	try:
		kerbsniff(config.interface,config.honey_username, config.domain, config.realm)
	except pyshark.capture.capture.TSharkCrashException:
		
		logging.error(message)
		raise DceptError(message)
		

if __name__ == "__main__":

	try:
		# Setup logging to file for troubleshooting
		logging.basicConfig(filename='/opt/dcept/var/dcept.log',format='%(asctime)s %(levelname)s %(message)s')

		# Mirror logging to console
		logging.getLogger().addHandler(logging.StreamHandler())

		main()
	except	(KeyboardInterrupt, DceptError):
		print
		logging.info("Shutting down DCEPT...")

