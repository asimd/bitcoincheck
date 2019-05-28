import requests
import time
from pybitcoin import BitcoinPrivateKey

keys = set()
with open('results.csv') as f:
    for line in f.read().split('\n'):
        if line:
            repo, file, pkey = line.split(",")
            keys.add(pkey)

for priv in keys:
    try:
        p = BitcoinPrivateKey(priv)
        pub = p.public_key().address()
        r = requests.get("https://blockchain.info/rawaddr/{}".format(pub))
        time.sleep(1)
        print "{} {} {:20} {:20} {:20}".format(priv, pub, r.json()['final_balance'], r.json()['total_received'], r.json()['total_sent'])
    except (AssertionError, IndexError):
        pass
    except ValueError:
        print r
        print r.text


