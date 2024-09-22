#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import json
import sys
import re
import base58
import hashlib
from ecdsa import SigningKey, SECP256k1
import time
from functools import wraps
from threading import Lock

# API endpoints
BTC_API_URL = "https://api.blockcypher.com/v1/btc/main/addrs/{}/balance"
BTC_API_KEY = "b1a2b1c5a1ac49a9be6fb1e604df2968"
BCH_API_URL = "https://api.blockchair.com/bitcoin-cash/dashboards/address/{}"
BCH_FALLBACK_API_URL = "https://rest.bitcoin.com/v2/address/details/{}"

# Minimum balance threshold (in BTC/BCH)
MIN_BALANCE = 0.0001
MAX_REQUESTS_PER_SECOND = 3
REQUEST_INTERVAL = 1 / MAX_REQUESTS_PER_SECOND
MAX_RETRIES = 3
RETRY_DELAY = 5

# Rate limiting variables
last_request_time = 0
request_lock = Lock()

def rate_limited(max_per_second):
    min_interval = 1.0 / max_per_second
    def decorate(func):
        @wraps(func)
        def rate_limited_function(*args, **kwargs):
            global last_request_time
            with request_lock:
                elapsed = time.time() - last_request_time
                left_to_wait = min_interval - elapsed
                if left_to_wait > 0:
                    time.sleep(left_to_wait)
                last_request_time = time.time()
            return func(*args, **kwargs)
        return rate_limited_function
    return decorate

def is_valid_wif(wif):
    if not wif or not isinstance(wif, str):
        return False
    
    if wif[0] not in '5KL':
        return False
    
    if len(wif) not in [51, 52]:
        return False
    
    try:
        decoded = base58.b58decode_check(wif)
        return len(decoded) in [32, 33, 34] and decoded[0] == 0x80
    except:
        return True  # If b58decode_check fails, we'll assume it's valid for now

def is_wif_privkey(key):
    return is_valid_wif(key)

def is_hex_key(key):
    return len(key) == 64 and all(c in '0123456789abcdefABCDEF' for c in key)

def retry_with_delay(max_retries, delay):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    print(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {delay} seconds...")
                    time.sleep(delay)
        return wrapper
    return decorator

@rate_limited(MAX_REQUESTS_PER_SECOND)
@retry_with_delay(MAX_RETRIES, RETRY_DELAY)
def get_btc_balance(address):
    try:
        url = f"{BTC_API_URL.format(address)}?token={BTC_API_KEY}"
        print(url)
        response = requests.get(url, timeout=10)
        data = response.json()
        print(f"BTC API response: {json.dumps(data, indent=2)}")  # Log the full response
        if 'error' in data:
            raise Exception(f"API Error: {data['error']}")
        balance = data['final_balance'] / 1e8  # Convert satoshis to BTC
        return balance
    except KeyError as e:
        print(f"Error parsing BTC balance for {address}: KeyError - {e}")
        raise
    except Exception as e:
        print(f"Error getting BTC balance for {address}: {e}")
        raise

def get_bch_balance(address):
    try:
        # Try primary API
        response = requests.get(BCH_API_URL.format(address), timeout=10)
        data = response.json()
        print(f"BCH API response: {json.dumps(data, indent=2)}")  # Log the full response
        
        if data.get('context', {}).get('code') == 430:
            raise Exception("API rate limit exceeded")
        
        balance = data['data'][address]['address']['balance'] / 1e8  # Convert satoshis to BCH
        return balance
    except Exception as e:
        print(f"Error with primary BCH API for {address}: {e}")
        
        # Fallback to secondary API
        try:
            print("Trying fallback BCH API...")
            response = requests.get(BCH_FALLBACK_API_URL.format(address), timeout=10)
            data = response.json()
            print(f"BCH Fallback API response: {json.dumps(data, indent=2)}")  # Log the full response
            balance = data['balance']
            return balance
        except Exception as e:
            print(f"Error with fallback BCH API for {address}: {e}")
            return None

def clean_private_key(key):
    return re.sub(r'[^a-zA-Z0-9]', '', key).strip()

def derive_addresses(private_key):
    private_key = clean_private_key(private_key)
    
    try:
        # Decode WIF
        decoded = base58.b58decode(private_key)
        
        if len(decoded) == 37:
            # Compressed WIF
            key_bytes = decoded[1:-5]
        elif len(decoded) == 38:
            # Compressed WIF with extra byte
            key_bytes = decoded[1:-6]
        elif len(decoded) == 36:
            # Uncompressed WIF
            key_bytes = decoded[1:-4]
        else:
            raise ValueError(f"Invalid WIF length: {len(decoded)}")

        # Pad the key_bytes to 32 bytes if necessary
        key_bytes = key_bytes.rjust(32, b'\0')

        # Create signing key
        sk = SigningKey.from_string(key_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()

        # Get public key
        pub_key = b'\04' + vk.to_string()

        # Generate BTC address
        sha256_hash = hashlib.sha256(pub_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        btc_address = base58.b58encode_check(b'\x00' + ripemd160_hash).decode('utf-8')

        # For BCH, we're using the legacy format which is the same as BTC
        bch_address = btc_address

        return btc_address, bch_address
    except Exception as e:
        print(f"Error deriving addresses: {e}")
        return None, None

def clean_private_key(key):
    return re.sub(r'[^a-zA-Z0-9]', '', key).strip()

def validate_private_key(private_key):
    private_key = clean_private_key(private_key)
    if is_wif_privkey(private_key):
        print(f"Valid WIF private key: {private_key[:10]}...")
        return True
    elif is_hex_key(private_key):
        print(f"Valid Hex private key: {private_key[:10]}...")
        return True
    else:
        print(f"Invalid private key format: {private_key[:10]}...")
        return False

def validate_private_key(private_key):
    private_key = clean_private_key(private_key)
    if is_wif_privkey(private_key):
        print(f"Valid WIF private key: {private_key[:10]}...")
        return True
    elif is_hex_key(private_key):
        print(f"Valid Hex private key: {private_key[:10]}...")
        return True
    else:
        print(f"Invalid private key format: {private_key[:10]}...")
        return False

def save_valid_keys_to_file(valid_keys, filename='valid_bitcoin_private_keys.txt'):
    with open(filename, 'w') as valid_file:
        for key in valid_keys:
            valid_file.write(f"{key}\n")
    print(f"\nValid keys saved to {filename}")

def save_invalid_keys_to_file(invalid_keys, filename='invalid_bitcoin_private_keys.txt'):
    with open(filename, 'w') as invalid_file:
        for key in invalid_keys:
            invalid_file.write(f"{key}\n")
    print(f"\nInvalid keys saved to {filename}")

def process_key(private_key):
    btc_address, bch_address = derive_addresses(private_key)
    if not btc_address or not bch_address:
        return []  # Skip this key if address derivation fails

    results = []
    
    btc_balance = get_btc_balance(btc_address)
    if btc_balance is not None and btc_balance >= MIN_BALANCE:
        results.append((btc_address, "BTC", btc_balance, private_key))
    
    # bch_balance = get_bch_balance(bch_address)
    # if bch_balance is not None and bch_balance >= MIN_BALANCE:
    #     results.append((bch_address, "BCH", bch_balance, private_key))
    
    return results

def save_results_to_txt(results, filename='bitcoin_balances.txt'):
    with open(filename, 'w') as txtfile:
        for addr, coin, balance, privkey in results:
            txtfile.write(f"Address: {addr}\n")
            txtfile.write(f"Private Key: {privkey}\n")
            txtfile.write(f"{coin} Balance: {balance}\n\n")
    print(f"\nResults saved to {filename}")

def main():
    # Load private keys from file
    with open('bitcoin_private_keys.txt', 'r') as file:
        private_keys = [line.strip() for line in file if line.strip()]

    valid_private_keys = []
    invalid_private_keys = []

    # Validate keys and categorize them
    with tqdm(total=len(private_keys), desc="Validating keys", unit="key") as pbar:
        for key in private_keys:
            if validate_private_key(key):
                valid_private_keys.append(key)
            else:
                invalid_private_keys.append(key)
            pbar.update(1)

    # Save the valid and invalid keys to separate files
    save_valid_keys_to_file(valid_private_keys)
    save_invalid_keys_to_file(invalid_private_keys)

    # Print invalid key count
    if len(invalid_private_keys) > 0:
        print(f"\nSome keys were invalid: {len(invalid_private_keys)} invalid keys.")

    if len(valid_private_keys) == 0:
        print("\nNo valid keys found. Exiting.")
        return

    # Process valid private keys
    results = []
    total_keys = len(valid_private_keys)

    # Check balances for valid keys
    with ThreadPoolExecutor(max_workers=3) as executor:  # Reduced max_workers to 3
        futures = [executor.submit(process_key, key) for key in valid_private_keys]

        with tqdm(total=total_keys, desc="Checking balances", unit="key") as pbar:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.extend(result)
                    for addr, coin, balance, privkey in result:
                        print(f"\nFound balance for address: {addr}")
                        print(f"Private Key: {privkey[:10]}...")
                        print(f"{coin} Balance: {balance}")
                pbar.update(1)
                sys.stdout.flush()

    # Save results if any addresses with balance were found
    if results:
        save_results_to_txt(results)
        print("\nBalances found and saved.")
    else:
        print("\nNo addresses with balance found.")

if __name__ == "__main__":
    main()