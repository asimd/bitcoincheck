Small python script to convert list of Bitcoin / Bitcoin Cash private keys into public addresses and check for current balance, total in and total out of that address. 

Install requirements: 
EDITED
```python
python 2.*
```

Usage:
```python
git clone git@github.com:asimd/bitcoincheck.git
pip install pybitcointools
python btc.py
```

This tool uses Google [BigQueryDB](https://cloud.google.com/bigquery/) query results as input. 
That input comes from scanning regex expression for all public Github repos matching the Bitcoin private key.

BigQueryDB query:
``` 
#standardSQL
SELECT f.repo_name, f.path, c.pkey
FROM `bigquery-public-data.github_repos.files` f JOIN
     (SELECT id,
             REGEXP_EXTRACT(content, r'(?:^|[^a-zA-Z0=9])(5[HJK][123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ]{48,49})(?:$|[^a-zA-Z0-9])') AS pkey
      FROM `bigquery-public-data.github_repos.contents`
      WHERE REGEXP_CONTAINS(content, r'(?:^|[^a-zA-Z0=9])(5[HJK][123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ]{48,49})(?:$|[^a-zA-Z0-9])')
     ) c
     ON f.id = c.id;

```



After that, it uses [Blockchain's](http://blockchain.com) public API for BTC and [BitBox's](https://rest.bitbox.earth) public API for BCH to check the balances for the given address.

Note: you may be rate limited if triggering too many ruquests, sign up for API key [HERE](https://api.blockchain.info/customer/signup) 


Usage Example:
![bitcoincheck](https://i.imgur.com/4hb1CRX.png)


Any suggestions, fixes or PR's are more then welcome.


Update: Added normalized CSV for testing purposes.
