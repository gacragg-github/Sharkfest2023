#!/usr/bin/python3

import time
import datetime
import socket
from socket import AF_INET, SOCK_DGRAM
import argparse
import six
from textwrap import TextWrapper
import ssl
import sslpsk
import struct
import threading
import concurrent.futures
import binascii
import sys
import base64

LocalIP = '172.16.0.106'

#Dummy key
BINARYPSK="super secret key material"
CLIENTIDENTITY="cd06891d123403f6e06ccba37deb5f1b"

#---------------------------------------------------------------------------------
# Parse CLI arguments
#---------------------------------------------------------------------------------
cliargs = argparse.ArgumentParser(description='Send arbitrary TCP/TLS requests')
cliargs.add_argument('-d', action='store_true', default=False, dest='DebugEnabled', help='Enable debug')
cliargs.add_argument('-p', action='store', default='7777', dest='TargetPort', help='TCP Port', type=int)
cliargs.add_argument('-delay', action='store', default='300', dest='Delay', help='Delay between samples [sec]', type=float)
cliargs.add_argument('-r', action='store', default='results', dest='ResultsFile', help='Result Filename-timestamp.csv')
cliargs.add_argument('-pass', action='store', default=None, dest='PSK', help='PSK for authentication (ASCII)')
cliargs.add_argument('-ck', action='store', dest='CLIENTIDENTITY', help='Client Identity (ASCII)')
cliargs.add_argument('-type', action='store', default='battery', dest='requesttype', help='request: battery | rssi')
cliargs.add_argument('-f', action='store', default=None, dest='CryptoFile', help='crypto file')
clioptions=cliargs.parse_args()


#---------------------------------------------------------------------------------
# #Subroutine to get current timestamp
#---------------------------------------------------------------------------------
def GetNow():						#For results filename
	CurrentTimestamp = datetime.datetime.now().strftime("%Y.%m.%d-%H.%M.%S")
	#CurrentTimestamp = datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")
	return CurrentTimestamp;

def GetNowData():					#For CSV output
	#CurrentTimestamp = datetime.datetime.now().strftime("%Y.%m.%d-%H.%M.%S")
	CurrentTimestamp = datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")
	return CurrentTimestamp;
	
#---------------------------------------------------------------------------------
# Read file of data to send
#---------------------------------------------------------------------------------
ResultsFileName=clioptions.ResultsFile
Results=open(ResultsFileName,'r+', buffering=1)

# Using readlines()
Lines = Results.readlines()

def legacy():
  
	count = 0
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM )
	sock.connect((LocalIP,clioptions.TargetPort))

	for line in Lines:
		count += 1
	
		# Strips the newline character
		# print("Line{}: {}".format(count, line.strip()))
		dataline = binascii.a2b_hex(line.strip())
	
		sock.send(dataline)
		time.sleep(0.01)

	sock.close()
	
def secure():

	if clioptions.CryptoFile:
		# Using readline()
		PSKFile = open(clioptions.CryptoFile, 'r')
		EncodedPSKfromFile = PSKFile.readline()
		KeyExpireFromFile = PSKFile.readline()
		EncodedClientIDFromFile = PSKFile.readline()
		PSKFile.close()
		PSKS=binascii.a2b_hex(binascii.hexlify(base64.b64decode(EncodedPSKfromFile)))
		CLIENTIDENTITYS=binascii.a2b_hex(binascii.hexlify(base64.b64decode(EncodedClientIDFromFile)))
	elif clioptions.PSK:						#CLI option
		PSKS=clioptions.PSK
		CLIENTIDENTITYS=clioptions.CLIENTIDENTITY
	else:									#Hardcoded value
		PSKS=binascii.a2b_hex(BINARYPSK)
		CLIENTIDENTITYS=CLIENTIDENTITY

	conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	conn.connect((LocalIP,clioptions.TargetPort))
	sock = sslpsk.wrap_socket(conn, ciphers='PSK-AES128-CBC-SHA', psk=(PSKS, CLIENTIDENTITYS))

	count = 0
	for line in Lines:
		dataline = binascii.a2b_hex(line.strip())	
		match count:
			case 0:
				time.sleep(4)
				count += 1
				continue
			case 1:
				time.sleep(4)
				count += 1
				continue
			case 2:
				count += 1
				time.sleep(2)		
			case _:
				count += 1
				time.sleep(0.01)
		sock.send(dataline)

	sock.setblocking(False)
	try:
		sock.unwrap()
	except ssl.SSLWantReadError:
		print('Got WantRead Error')
	else:
		assert False
	sock.shutdown(socket.SHUT_RDWR)
	sock.close()
	time.sleep(2)
	

def main():
	
	#legacy()
	secure()
		
if __name__ == "__main__":
	
	main()
