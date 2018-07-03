"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""

from .ecWrapper import PrivateKey
from .comm import getDongle
from .deployed import getDeployedSecretV1, getDeployedSecretV2
from .hexLoader import HexLoader
import argparse
import binascii
import sys

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--targetId", help="Set the chip target ID", type=auto_int)
parser.add_argument("--appName", help="Set the application name")
parser.add_argument("--appHash", help="Set the application hash")
parser.add_argument("--rootPrivateKey", help="Set the root private key")
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
parser.add_argument("--deployLegacy", help="Use legacy deployment API", action='store_true')

args = parser.parse_args()

if args.appName is None and args.appHash is None:
	raise Exception("Missing appName or appHash")
if (not args.appName is None) and (not args.appHash is None):
	raise Exception("Set either appName or appHash")
    
if not args.appName is None:
	if (sys.version_info.major == 3):
		args.appName = bytes(args.appName,'ascii')
	if (sys.version_info.major == 2):
		args.appName = bytes(args.appName)

if not args.appHash is None:
	if (sys.version_info.major == 3):
		args.appHash = bytes(args.appHash,'ascii')
	if (sys.version_info.major == 2):
		args.appHash = bytes(args.appHash)
	# decode hex hash
	args.appHash = bytearray.fromhex(args.appHash)

if args.targetId == None:
	args.targetId = 0x31000002
if args.rootPrivateKey == None:
	privateKey = PrivateKey()
	publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
	print("Generated random root public key : %s" % publicKey)
	args.rootPrivateKey = privateKey.serialize()

dongle = getDongle(args.apdu)

if args.deployLegacy:
	secret = getDeployedSecretV1(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
else:
	secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
loader = HexLoader(dongle, 0xe0, True, secret)
if not args.appName is None:
	"""
	# if platform supports code/data split, then must delete with hash, list app first
	applist = []
	first = True
	while True:
		apps = loader.listApp(first)
		first=False
		if len(apps) != 0:
			applist += apps
		else:
			break
	#if no hash code data (or no app) 
	if len(applist) == 0 or not 'hash_code_data' in applist[0]:
		loader.deleteApp(args.appName)
	else:
		#search for app with given name and delete by hash
		for app in applist:
			if app['name'] == args.appName:
				loader.deleteAppByHash(app['hash'])
				sys.exit(0)
		raise BaseException("Application not found")
	"""
	loader.deleteApp(args.appName)
if not args.appHash is None:
	loader.deleteAppByHash(args.appHash)