import sys
import argparse
import os
import struct
import urllib2, urlparse
from BlueHSMServer_pb2 import Request, Response, Parameter
from ledgerblue.comm import getDongle

def auto_int(x):
    return int(x, 0)

def serverQuery(request, url):
	data = request.SerializeToString()
	urll = urlparse.urlparse(args.url)
	req = urllib2.Request(args.url, data, {"Content-type": "application/octet-stream" })
	res = urllib2.urlopen(req)
	data = res.read()
	response = Response()
	response.ParseFromString(data)
	if len(response.exception) <> 0:
		raise Exception(response.exception)
	return response


parser = argparse.ArgumentParser()
parser.add_argument("--url", help="Server URL")
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
parser.add_argument("--perso", help="Personalization key reference to use")
parser.add_argument("--firmware", help="Firmware reference to use")
parser.add_argument("--targetId", help="Set the chip target ID", type=auto_int)
parser.add_argument("--firmwareKey", help="Firmware reference key to use")
#parser.add_argument("--scpv2", help="Enable SCP protocol version 2", action='store_true')

args = parser.parse_args()
if args.url == None:
	raise Exception("No URL specified")
if args.perso == None:
	raise Exception("No personalization specified")
if args.firmware == None:
	raise Exception("No firmware specified")
if args.firmwareKey == None:
	raise Exception("No firmware key specified")
if args.targetId == None:
	args.targetId = 0x31000002 # Ledger Blue by default

# guess scp version from the target id
args.scpv2 = False
if (args.targetId & 0xF) >= 3:
	args.scpv2 = True

dongle = getDongle(args.apdu)

# Identify

targetid = bytearray(struct.pack('>I', args.targetId))
apdu = bytearray([0xe0, 0x04, 0x00, 0x00]) + bytearray([len(targetid)]) + targetid
dongle.exchange(apdu)

# Get nonce and ephemeral key

request = Request()
request.reference = "distributeFirmware11_v2"
parameter = request.remote_parameters.add()
parameter.local = False
parameter.alias = "persoKey"
parameter.name = args.perso
if args.scpv2:
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "scpv2"
	parameter.name = "dummy"
request.largeStack = True

response = serverQuery(request, args.url)

offset = 0

remotePublicKey = response.response[offset : offset + 65]
offset += 65
nonce = response.response[offset : offset + 8]
if args.scpv2:
	offset += 8
	masterPublicKey = response.response[offset : offset + 65]
	offset += 65
	masterPublicKeySignatureLength = ord(response.response[offset + 1]) + 2
	masterPublicKeySignature = response.response[offset : offset + masterPublicKeySignatureLength]

# Initialize chain 

apdu = bytearray([0xe0, 0x50, 0x00, 0x00, 0x08]) + nonce
deviceInit = dongle.exchange(apdu)
deviceNonce = deviceInit[4 : 4 + 8]


# # send the self signed certificate, not needed, and if not done then the dongle won't consider the HSM as a foreign key, it will feil earlier, enabling to probe for the key to use
# if args.scpv2:
# 	certificate = bytearray([len(masterPublicKey)]) + masterPublicKey + bytearray([len(masterPublicKeySignature)]) + masterPublicKeySignature
# 	apdu = bytearray([0xE0, 0x51, 0x00, 0x00]) + bytearray([len(certificate)]) + certificate
# 	dongle.exchange(apdu)

# Get remote certificate

request = Request()
request.reference = "distributeFirmware11_v2"
request.id = response.id
parameter = request.remote_parameters.add()
parameter.local = False
parameter.alias = "persoKey"
parameter.name = args.perso
request.parameters = str(deviceNonce)
request.largeStack = True

response = serverQuery(request, args.url)

offset = 0

remotePublicKeySignatureLength = ord(response.response[offset + 1]) + 2
remotePublicKeySignature = response.response[offset : offset + remotePublicKeySignatureLength]

certificate = bytearray([len(remotePublicKey)]) + remotePublicKey + bytearray([len(remotePublicKeySignature)]) + remotePublicKeySignature
apdu = bytearray([0xE0, 0x51, 0x80, 0x00]) + bytearray([len(certificate)]) + certificate
dongle.exchange(apdu)

# Walk the chain

index = 0
while True:
		if index == 0:
			certificate = bytearray(dongle.exchange(bytearray.fromhex('E052000000')))
		elif index == 1:
			certificate = bytearray(dongle.exchange(bytearray.fromhex('E052800000')))
		else:
				break
		if len(certificate) == 0:
			break
		request = Request()
		request.reference = "distributeFirmware11_v2"
		request.id = response.id
		request.parameters = str(certificate)
		request.largeStack = True
		serverQuery(request, args.url)
		index += 1

# Commit agreement and send firmware

request = Request()
request.reference = "distributeFirmware11_v2"
parameter = request.remote_parameters.add()
parameter.local = False
parameter.alias = "firmware"
parameter.name = args.firmware
parameter = request.remote_parameters.add()
parameter.local = False
parameter.alias = "firmwareKey"
parameter.name = args.firmwareKey
if args.scpv2:
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "scpv2"
	parameter.name = "dummy"
request.id = response.id
request.largeStack = True

response = serverQuery(request, args.url)
responseData = bytearray(response.response)

dongle.exchange(bytearray.fromhex('E053000000'))

offset = 0 
while offset < len(responseData):
	apdu = responseData[offset : offset + 5 + responseData[offset + 4]]
	dongle.exchange(apdu)
	offset += 5 + responseData[offset + 4]

