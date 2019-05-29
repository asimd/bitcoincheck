import requests
import time
from pybitcoin import BitcoinPrivateKey

keys = set()
with open('example.csv') as f:
    for line in f.read().split('\n'):
        if line:
            repo, file, pkey = line.split(",")
            keys.add(pkey)

for priv in keys:
    try:
        p = BitcoinPrivateKey(priv)
        pub = p.public_key().address()
        r = requests.get("https://rest.bitcoin.com/v2/address/details/{}".format(pub))
        print ("Bch Key: {}  Public Address: {}      Balance: {}  Total In: {}    Total Out: {}".format(priv, pub, r.json()['balance'], r.json()['totalReceived'], r.json()['totalSent']))
        time.sleep(5)   
    except (AssertionError, IndexError):
        pass
    except ValueError:
        print r
        print r.text


