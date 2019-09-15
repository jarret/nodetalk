#!/usr/bin/env python3

# MIT License something something

import os
import sys
import json
import hashlib

import argparse

from bitcoin.wallet import CBitcoinSecret
from bitcoin.signmessage import SignMessage, VerifyMessage, BitcoinMessage
from bitcoin.core.key import CPubKey

import base64
from electrum.bitcoin import pubkey_to_address

from Crypto.Hash import SHA256
from Crypto.Hash import HMAC


MSG = """-----BEGIN BITCOIN SIGNED MESSAGE-----
{somejson}
-----BEGIN SIGNATURE-----
<bitcoin_addr>
<signature>
-----END BITCOIN SIGNED MESSAGE-----"""


MSG_START = "-----BEGIN BITCOIN SIGNED MESSAGE-----"

SIG_START = "-----BEGIN SIGNATURE-----"

MSG_END = "-----END BITCOIN SIGNED MESSAGE-----"

REGEX = "%s\n(.*)\n%s\n(.*)\n(.*)\n%s" % (MSG_START, SIG_START, MSG_END)


def signed_msg(msg_txt, addr, privkey):
    sig = SignMessage(privkey, BitcoinMessage(msg_txt)).decode('utf-8')
    s = MSG_START + "\n"
    s += msg_txt + "\n"
    s += SIG_START + "\n"
    s += addr + "\n"
    s += sig + "\n"
    s += MSG_END + "\n"
    return s


class SigVerify(object):
    def __init__(self, address, message, sig):
        self.address = address
        self.message = message
        self.sig = sig

    def is_valid(self):
        mb = BitcoinMessage(self.message)
        sig = base64.b64decode(self.sig)
        message_hash = mb.GetHash()

        #print("hash: %s" % message_hash.hex())
        pubkey = CPubKey.recover_compact(message_hash, sig)
        if not pubkey:
            return False
        #print("pubkey: %s" % pubkey.hex())
        if pubkey.hex() == self.address:
            return True
        for txin_type in ['p2pkh','p2wpkh','p2wpkh-p2sh']:
            addr = pubkey_to_address(txin_type, pubkey.hex())
            if addr == str(self.address):
                return True
        return False


class HKDF_SHA256(object):
    """ follows how c-lightning derives keys from hsm_secret in a sloppy way """
    def __init__(self, hsm_secret):
        salt = b'\0' * 32
        self.prk = HMAC.new(salt, hsm_secret, digestmod=SHA256).digest()

    def extract_key(self):
        c = 1
        bib = c.to_bytes(1, byteorder='big', signed=False)
        stuff = b'n' + b'o' + b'd' + b'e' + b'i' + b'd' + bib
        return HMAC.new(self.prk, stuff, digestmod=SHA256).digest()


def sign(s):
    if not os.path.exists(s.hsm_secret) and os.path.isfile(s.hsm_secret):
        sys.exit("not a file? %s" % s.hsm_secret)

    if os.path.getsize(s.hsm_secret) != 32:
        sys.exit("not private key file? %s" % s.hsm_secret)

    f = open(s.hsm_secret, "rb")
    hsm_secret = f.read(32)
    f.close()

    node_priv_key = HKDF_SHA256(hsm_secret).extract_key()

    priv_key = CBitcoinSecret.from_secret_bytes(node_priv_key)
    pub_key = priv_key.pub

    #print("pub: %s" % pub_key.hex())
    #addr = pubkey_to_address("p2wpkh", pub_key.hex())
    #print("addr: %s" % addr)

    msg = signed_msg(s.message, pub_key.hex(), priv_key)
    print(msg)


def verify(s):
    sv = SigVerify(s.node_id, s.message, s.signature)
    print(sv.is_valid())



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="nodetalk.py")
    subparsers = parser.add_subparsers(help='sub-command help')

    s_parser = subparsers.add_parser('sign',
                                     help='sign a message the node_id '
                                          'corresponding to the hsm_secret')
    s_parser.add_argument("hsm_secret", type=str,
                        help="private key file of c-lightning node")
    s_parser.add_argument("message", type=str,
                          help="message to sign")
    s_parser.set_defaults(func=sign)


    v_parser = subparsers.add_parser('verify',
                                     help='verify a signed message '
                                          'from a node_id or btc addr')
    v_parser.add_argument("message", type=str, help="message to verify")
    v_parser.add_argument("node_id", type=str, help="node_id of sending node")
    v_parser.add_argument("signature", type=str, help="signature")
    v_parser.set_defaults(func=verify)

    s = parser.parse_args()
    if not hasattr(s, "func"):
        parser.print_help()
        sys.exit("* did not specify subcommand")
    s.func(s)
