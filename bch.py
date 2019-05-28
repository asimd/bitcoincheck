import requests
import time
from pybitcoin import BitcoinPrivateKey

keys = set()
with open('results.csv') as f:
    for line in f.read().split('\n'):
        if line:
            repo, file, pkey = line.split(",")
            keys.add(pkey)

print "Bch Key\t\t\t\t\t\t Public Address\t\t\t\t\t Balance:\t Total In:\t Total Out: \n"

for priv in keys:
    try:
        p = BitcoinPrivateKey(priv)
        pub = p.public_key().address()
        r = requests.get("https://rest.bitbox.earth/v1/address/details/{}".format(pub))
        time.sleep(1)   
        print "{} {} {:20} {:20} {:20}".format(priv, pub, r.json()['balance'], r.json()['totalReceived'], r.json()['totalSent'])
    except (AssertionError, IndexError):
        pass
    except ValueError:
        print r
        print r.text


