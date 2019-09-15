# nodetalk
A script for signing and verifying message from Lightning Network node ids using the c-lightning hsm_secret file


# overview:

A slap-happy script proof-of-concept that follows the `hkdf_sha256`/ RFC5869 hardened key derivation script of c-lightning to make the `node_id` public/private key pair from the `hsm_secret` file in the lightning-dir.

It uses the public/private key pair to sign a message using `python-bitcoinlib` and also Frankensteins in some code from Electrum to turn the public key into 'p2pkh', 'p2wpkh' or 'p2wpkh-p2sh' addresses.


# example:

```
(ins)jarret@renn:~/git/nodetalk$ ./nodetalk.py -h
usage: nodetalk.py [-h] {sign,verify} ...

positional arguments:
  {sign,verify}  sub-command help
    sign         sign a message the node_id corresponding to the hsm_secret
    verify       verify a signed message from a node_id or btc addr

optional arguments:
  -h, --help     show this help message and exit
(ins)jarret@renn:~/git/nodetalk$ ./nodetalk.py sign -h
usage: nodetalk.py sign [-h] hsm_secret message

positional arguments:
  hsm_secret  private key file of c-lightning node
  message     message to sign

optional arguments:
  -h, --help  show this help message and exit
(ins)jarret@renn:~/git/nodetalk$ ./nodetalk.py verify -h
usage: nodetalk.py verify [-h] message node_id signature

positional arguments:
  message     message to verify
  node_id     node_id of sending node
  signature   signature

optional arguments:
  -h, --help  show this help message and exit
(ins)jarret@renn:~/git/nodetalk$ ./nodetalk.py sign ~/lightningd-run/lightning-dir/hsm_secret "Validating nodes have a say in the network."
-----BEGIN BITCOIN SIGNED MESSAGE-----
Validating nodes have a say in the network.
-----BEGIN SIGNATURE-----
035c77dc0a10fe60e1304ae5b57d8fef87751add5d016b896d854fb706be6fc96c
Hw5C9Nymyi+JAaLlj2YDBWEoFv67s7bK7qAhMRlItnEJMXiI+WAVbw8ukKifeCx2j4TzG/CssXLow2IQS1rs6Q8=
-----END BITCOIN SIGNED MESSAGE-----

(ins)jarret@renn:~/git/nodetalk$ ./nodetalk.py verify "Validating nodes have a say in the network." 035c77dc0a10fe60e1304ae5b57d8fef87751add5d016b896d854fb706be6fc96c Hw5C9Nymyi+JAaLlj2YDBWEoFv67s7bK7qAhMRlItnEJMXiI+WAVbw8ukKifeCx2j4TzG/CssXLow2IQS1rs6Q8=
True
(ins)jarret@renn:~/git/nodetalk$ ./nodetalk.py verify "Validating nodes don't have a say in the network." 035c77dc0a10fe60e1304ae5b57d8fef87751add5d016b896d854fb706be6fc96c Hw5C9Nymyi+JAaLlj2YDBWEoFv67s7bK7qAhMRlItnEJMXiI+WAVbw8ukKifeCx2j4TzG/CssXLow2IQS1rs6Q8=
False
(ins)jarret@renn:~/git/nodetalk$ 
```
