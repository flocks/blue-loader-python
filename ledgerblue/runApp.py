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
from .hexParser import IntelHexParser, IntelHexPrinter
from .hexLoader import HexLoader
from .deployed import getDeployedSecretV1, getDeployedSecretV2
import argparse
import struct
import binascii
import sys

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--targetId", help="Set the chip target ID", type=auto_int)
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
parser.add_argument("--rootPrivateKey", help="Set the root private key")
parser.add_argument("--appName", help="Name of the application to run")


args = parser.parse_args()

if args.targetId is None:
	args.targetId = 0x31000002
if args.rootPrivateKey is None:
	privateKey = PrivateKey()
	publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
	print("Generated random root public key : %s" % publicKey)
	args.rootPrivateKey = privateKey.serialize()
if args.appName is None:
	raise Exception("Missing appname to run")


dongle = getDongle(args.apdu)

secret=None
#secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
loader = HexLoader(dongle, 0xe0, False, secret)

loader.runApp(args.appName)
