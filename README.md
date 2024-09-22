## Bitcoin and Bitcoin Cash Private Key to Address with Balance Checker

This Python script checks the balance of Bitcoin (BTC) and Bitcoin Cash (BCH) addresses derived from private keys (both WIF and hex formats). The script uses the BlockCypher API for BTC and BlockChair with fallback to Bitcoin.com for BCH balances. It also performs rate-limited API calls, retries on failure, and saves valid private keys along with their respective balances.

## Features

- **Private Key Validation**: Supports both WIF and hex private key formats.
- **Address Derivation**: Derives Bitcoin and Bitcoin Cash addresses from private keys.
- **Balance Checking**: Queries the BTC and BCH networks for address balances.
- **Multi-threaded Execution**: Processes multiple private keys in parallel using Python's `concurrent.futures`.
- **Rate Limiting**: Prevents exceeding API rate limits.
- **Error Handling**: Automatically retries on API failures.
- **Key Classification**: Saves valid and invalid private keys to separate files.
- **Balance Results**: Outputs the addresses with balances to a text file.

## Prerequisites

- Python 3.x
- `requests` module
- `tqdm` module
- `ecdsa` module
- `base58` module
- An API key from [BlockCypher](https://www.blockcypher.com/) (for Bitcoin balance checking)

### Installing Dependencies

To install the required dependencies, run:

```bash
pip install requests tqdm ecdsa base58
```

### API Key Setup
To query the Bitcoin balance, you'll need a BlockCypher API key. You can generate a free one by creating an account at BlockCypher. Then, replace the placeholder in the script with your API key:

```
BTC_API_KEY = "your-api-key-here"
```

### How to Use
## How to Use

1. **Prepare a File with Private Keys**: The script reads private keys from a file called `bitcoin_private_keys.txt`. Each private key should be on a new line.
   
   Example:


2. **Run the Script**:
```bash
python3 bitcoin_balance_checker.py
```

3. **Check the Results**:
   - The script will classify private keys as valid or invalid.
   - It will check the balance of valid private keys and save the results to `bitcoin_balances.txt`.
   - Invalid private keys will be saved to `invalid_bitcoin_private_keys.txt`.

### Output Files:

- `valid_bitcoin_private_keys.txt`: Contains valid private keys that passed validation checks.
- `invalid_bitcoin_private_keys.txt`: Contains private keys that failed validation.
- `bitcoin_balances.txt`: Contains Bitcoin addresses with non-zero balances, including their associated private keys.

Each entry in `bitcoin_balances.txt` includes:

- **Address**: The Bitcoin address derived from the private key.
- **Private Key**: The private key associated with the address.
- **BTC Balance**: The Bitcoin balance (if non-zero).

## Script Overview

### Key Functions:

- **Private Key Validation**: 
  - `is_valid_wif(key)`: Validates WIF private keys based on format and length.
  - `is_hex_key(key)`: Validates hex-format private keys (64 characters long and hexadecimal).

- **Address Derivation**:
  - `derive_addresses(private_key)`: Derives Bitcoin and Bitcoin Cash addresses from a private key, using the ECDSA and SECP256k1 curve.

- **Balance Checking**:
  - `get_btc_balance(address)`: Fetches the BTC balance of an address from BlockCypher's API.
  - `get_bch_balance(address)`: Fetches the BCH balance of an address from BlockChair's API, with a fallback to Bitcoin.com's API if needed.

- **Parallel Processing**: 
  The script uses `ThreadPoolExecutor` to check balances of multiple keys concurrently, making the script faster when handling a large number of private keys.

- **Rate Limiting & Retries**:
  - `rate_limited()`: A decorator to ensure API calls do not exceed a specified rate (e.g., 3 requests per second).
  - `retry_with_delay()`: A decorator that retries API calls if they fail, with a specified delay between attempts.

## Contribution

If you'd like to contribute to this project, feel free to submit a pull request or raise an issue. Contributions are welcome!

## License

This project is licensed under the MIT License. You are free to use, modify, and distribute the code in compliance with the license.

---

**Disclaimer**: This script is for educational and research purposes only. Please ensure you comply with relevant laws and terms of service for any APIs you use, and be responsible when handling
