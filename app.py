from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from mnemonic import Mnemonic
import requests
from web3 import EthereumTesterProvider, Web3, HTTPProvider
from web3.auto import w3
from eth_account import Account

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import os
from bson import ObjectId

import pymongo
import bcrypt
import random

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["wallet1"]
users = db.users
accounts = db.accounts

INFURA_ID = os.getenv('INFURA_ID')

Account.enable_unaudited_hdwallet_features()

def get_eth_price_usd(coin):
    url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin}&vs_currencies=usd"
    print(url)
    response = requests.get(url)
    data = response.json()
    print(data)
    price_usd = data.get(coin, {}).get("usd", "Price not available")
    return price_usd


def get_wallet_balance(address, chain="sepolia"):
    # Connect to Goerli Testnet
    infura_url = "https://{}.infura.io/v3/{}".format(chain, INFURA_ID)
    web3 = Web3(HTTPProvider(infura_url))

    # Check if connected to Goerli
    if web3.is_connected():
        print("Connected to Sepolia Testnet")
    else:
        print("Failed to connect to Sepolia Testnet")

    # Check account balance
    balance = web3.eth.get_balance(address)
    print("Account Balance:", web3.from_wei(balance, 'ether'), "ETH")
    return web3.from_wei(balance, 'ether')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/new_account', methods=['GET'])
def new_account():
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=128)
    session['mnemonic'] = mnemonic

    return render_template('new_account.html', mnemonic=mnemonic)

@app.route('/existing_account', methods=['GET', 'POST'])
def existing_account():
    random_numbers = random.sample(range(1, 13), 12)
    session['random_numbers'] = random_numbers
    return render_template('existing_account.html', random_numbers=random_numbers)

@app.route('/set_password', methods=['GET'])
def set_password():
    random_numbers = random.sample(range(1, 13), 5)
    session['random_numbers'] = random_numbers
    return render_template('set_password.html', random_numbers=random_numbers)

@app.route('/verify_new_mnemonic', methods=['POST'])
def verify_new_mnemonic():
    random_numbers = session.get('random_numbers', [])
    print("random_numbers:", random_numbers)

    mnemonic = session.get("mnemonic")
    mnemonics = mnemonic.split(" ")

    flag_count = 0
    for i in random_numbers:
        if request.form.get(f"mnemonic{str(i)}")!= None:
            if request.form.get(f"mnemonic{str(i)}") == mnemonics[i-1]:
                flag_count += 1
    
    if flag_count == 5:
        # Encrypt mnemonic
        password = request.form['password']

        # Derive key from password
        salt = get_random_bytes(16)  # Generate a random salt
        key = PBKDF2(password, salt, dkLen=32)  # Derive a key

        # Encrypt the mnemonic
        cipher = AES.new(key, AES.MODE_EAX, nonce=b"1")
        ciphertext, tag = cipher.encrypt_and_digest(mnemonic.encode('utf-8'))

        # Store encrypted mnemonic, salt, and tag in MongoDB
        encrypted_mnemonic = base64.b64encode(ciphertext).decode('utf-8')
        encrypted_salt = base64.b64encode(salt).decode('utf-8')
        encrypted_tag = base64.b64encode(tag).decode('utf-8')

        user_id = users.insert_one({
            "password": password,
            "encrypted_mnemonic": encrypted_mnemonic,
            "salt": encrypted_salt,
            "tag": encrypted_tag
        }).inserted_id
        print("User ID:", user_id)

        account = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/0")
        print("Account Address:", account.address)
        print("Private Key:", account._private_key.hex())

        salt = get_random_bytes(16)  # Generate a random salt
        key = PBKDF2(encrypted_mnemonic, salt, dkLen=32)  # Derive a key

        # Encrypt the private key
        private_key = account._private_key.hex()  # Private key to be encrypted
        cipher = AES.new(key, AES.MODE_EAX, nonce=b"1")  # Create a new AES cipher
        ciphertext, tag = cipher.encrypt_and_digest(bytes(private_key, 'utf-8'))

        # Store encrypted private key and salt in MongoDB
        encrypted_private_key = base64.b64encode(ciphertext).decode('utf-8')
        encrypted_salt = base64.b64encode(salt).decode('utf-8')
        encrypted_tag = base64.b64encode(tag).decode('utf-8')

        account_id = accounts.insert_one({
            "user_id": ObjectId(str(user_id)),
            "address": account.address,
            "encrypted_private_key": encrypted_private_key,
            "salt": encrypted_salt,
            "tag": encrypted_tag
        }).inserted_id

        session['user_id'] = str(user_id)
        session['password'] = str(password)

        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('set_password'), msg="Invalid Mnemonic")



@app.route('/verify_existing_mnemonic', methods=['POST'])
def verify_existing_mnemonic():
    random_numbers = session.get('random_numbers', [])
    print("random_numbers:", random_numbers)

    mnemonics = []

    for i in range(1, 13):
        if request.form.get(f"mnemonic{str(i)}")!= None:
            mnemonics.append(request.form.get(f"mnemonic{str(i)}"))
    
    if len(mnemonics) == 12:
        # Encrypt mnemonic
        password = request.form['password']
        mnemonic = " ".join(mnemonics)

        # Derive key from password
        salt = get_random_bytes(16)  # Generate a random salt
        key = PBKDF2(password, salt, dkLen=32)  # Derive a key

        # Encrypt the mnemonic
        cipher = AES.new(key, AES.MODE_EAX, nonce=b"1")
        ciphertext, tag = cipher.encrypt_and_digest(mnemonic.encode('utf-8'))

        # Store encrypted mnemonic, salt, and tag in MongoDB
        encrypted_mnemonic = base64.b64encode(ciphertext).decode('utf-8')
        encrypted_salt = base64.b64encode(salt).decode('utf-8')
        encrypted_tag = base64.b64encode(tag).decode('utf-8')

        user_id = users.insert_one({
            "password": password,
            "encrypted_mnemonic": encrypted_mnemonic,
            "salt": encrypted_salt,
            "tag": encrypted_tag
        }).inserted_id
        print("User ID:", user_id)

        account = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/0")
        print("Account Address:", account.address)
        print("Private Key:", account._private_key.hex())

        salt = get_random_bytes(16)  # Generate a random salt
        key = PBKDF2(encrypted_mnemonic, salt, dkLen=32)  # Derive a key

        # Encrypt the private key
        private_key = account._private_key.hex()  # Private key to be encrypted
        cipher = AES.new(key, AES.MODE_EAX, nonce=b"1")  # Create a new AES cipher
        ciphertext, tag = cipher.encrypt_and_digest(bytes(private_key, 'utf-8'))

        # Store encrypted private key and salt in MongoDB
        encrypted_private_key = base64.b64encode(ciphertext).decode('utf-8')
        encrypted_salt = base64.b64encode(salt).decode('utf-8')
        encrypted_tag = base64.b64encode(tag).decode('utf-8')

        account_id = accounts.insert_one({
            "user_id": ObjectId(str(user_id)),
            "address": account.address,
            "encrypted_private_key": encrypted_private_key,
            "salt": encrypted_salt,
            "tag": encrypted_tag
        }).inserted_id

        session['user_id'] = str(user_id)
        session['password'] = str(password)

        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('set_password'), msg="Invalid Mnemonic")


@app.route('/api/add_new_account', methods=['POST'])
def add_new_account():
    
    user_id = request.json.get("user_id")

    user_data = users.find_one({"_id": ObjectId(user_id)})
    if user_data is None:
        return jsonify({"status": "error", "message": "User does not exist"})
    
    total_account = accounts.count_documents({"user_id": ObjectId(user_id)})
    print("total_account", total_account)
    if total_account >= 10:
        return jsonify({"status": "error", "message": "You have reached the maximum number of accounts"})
    
    print(user_data['encrypted_mnemonic'])
    encrypted_mnemonic = user_data['encrypted_mnemonic']
    encrypted_salt = user_data['salt']
    encrypted_tag = user_data['tag']
    password = user_data['password']

    # Derive the same key using user's password
    # Decode the stored base64 encoded values
    ciphertext = base64.b64decode(encrypted_mnemonic)
    salt = base64.b64decode(encrypted_salt)
    tag = base64.b64decode(encrypted_tag)

    print(salt, tag, ciphertext)

    # Derive the key using PBKDF2 and the same password and salt
    key = PBKDF2(password, salt, dkLen=32)

    # Decrypt the mnemonic 
    cipher = AES.new(key, AES.MODE_EAX, nonce=b"1")
    decrypted_mnemonic_bytes = cipher.decrypt_and_verify(ciphertext, tag)

    decrypted_mnemonic = decrypted_mnemonic_bytes.decode('utf-8')
    print("Decrypted Mnemonic:", decrypted_mnemonic)
    account = Account.from_mnemonic(decrypted_mnemonic, account_path=f"m/44'/60'/0'/0/{total_account}")
    print("Account Address:", account.address)
    print("Private Key:", account._private_key.hex())

    salt = get_random_bytes(16)  # Generate a random salt
    key = PBKDF2(encrypted_mnemonic, salt, dkLen=32)  # Derive a key

    # Encrypt the private key
    private_key = account._private_key.hex()  # Private key to be encrypted
    cipher = AES.new(key, AES.MODE_EAX, nonce=b"1")  # Create a new AES cipher
    ciphertext, tag = cipher.encrypt_and_digest(bytes(private_key, 'utf-8'))

    # Store encrypted private key and salt in MongoDB
    encrypted_private_key = base64.b64encode(ciphertext).decode('utf-8')
    encrypted_salt = base64.b64encode(salt).decode('utf-8')
    encrypted_tag = base64.b64encode(tag).decode('utf-8')

    account_id = accounts.insert_one({
        "user_id": ObjectId(user_id),
        "address": account.address,
        "encrypted_private_key": encrypted_private_key,
        "salt": encrypted_salt,
        "tag": encrypted_tag
    }).inserted_id

    return jsonify({"status": "success", "message": "New account added successfully", "address": account.address})



@app.route('/api/send_crypto', methods=['POST'])
def send_crypto():
    sAddress = request.json.get("sAddress")
    rAddress = request.json.get("rAddress")
    amount_in_ether = request.json.get("amount_in_ether")
    user_id = request.json.get("user_id")
    chain = request.json.get("chain")

    print(sAddress, rAddress, amount_in_ether)

    # Connect to the Ethereum network (this example uses the Rinkeby testnet)
    infura_url = "https://{}.infura.io/v3/{}".format(chain, INFURA_ID)
    web3 = Web3(Web3.HTTPProvider(infura_url))

    # Ensure the connection is successful
    if web3.is_connected() == False:
        return jsonify({"status": "error", "message": "Web3 is not connected"})

    # read private key from db
    account_data = accounts.find_one({"user_id": ObjectId(user_id), "address": sAddress})
    if account_data is None:
        return jsonify({"status": "error", "message": "Account does not exist"})
    
    user_data = users.find_one({"_id": ObjectId(user_id)})
    if user_data is None:
        return jsonify({"status": "error", "message": "User does not exist"})
 
    encrypted_mnemonic = user_data['encrypted_mnemonic']
    encrypted_private_key = account_data['encrypted_private_key']
    encrypted_salt = account_data['salt']
    encrypted_tag = account_data['tag']
    password = user_data['password']

    print(encrypted_private_key, encrypted_salt, encrypted_tag, password)

    # Decode the stored base64 encoded values
    ciphertext = base64.b64decode(encrypted_private_key)
    salt = base64.b64decode(encrypted_salt)
    tag = base64.b64decode(encrypted_tag)

    print(salt, tag, ciphertext)

    # Derive the key using PBKDF2 and the same password and salt
    key = PBKDF2(encrypted_mnemonic, salt, dkLen=32)

    # Decrypt the mnemonic 
    cipher = AES.new(key, AES.MODE_EAX, nonce=b"1")
    decrypted_pk_bytes = cipher.decrypt_and_verify(ciphertext, tag)

    sender_private_key = decrypted_pk_bytes.decode('utf-8')

    # Transaction details
    nonce = web3.eth.get_transaction_count(sAddress)
    gas_price = web3.eth.gas_price
    gas_limit = 21000  # 21000 is the gas limit for standard transactions

    # Convert the amount in Ether to Wei
    value = web3.to_wei(amount_in_ether, 'ether')

    # Create the transaction dictionary
    tx = {
        'nonce': nonce,
        'to': rAddress,
        'value': value,
        'gas': gas_limit,
        'gasPrice': gas_price,
    }

    # Sign the transaction with the private key
    signed_tx = web3.eth.account.sign_transaction(tx, sender_private_key)

    # Send the transaction
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    if tx_receipt['status'] != 1:
            return False, "Transaction Failed"

    # Get the transaction hash
    print(f"Transaction hash: {web3.to_hex(tx_hash)}")

    return jsonify({"status": "success", "message": "Transaction successfully", "txnhash": web3.to_hex(tx_hash)})





# Add other routes as necessary

@app.route('/dashboard')
def dashboard():
    # Retrieve encrypted data from MongoDB
    user_id = session.get("user_id")
    print(user_id)

    wallet_array = []
    accounts_data = accounts.find({"user_id": ObjectId(user_id)})
    print(accounts_data)
    for ed in accounts_data:
        wallet_array.append(ed['address'])
    #encrypted_private_key = base64.b64decode(encrypted_data['encrypted_private_key'])
    #salt = base64.b64decode(encrypted_data['salt'])
    #tag = base64.b64decode(encrypted_data['tag'])

    # Derive the same key using user's password
    #password = session.get("password")
    #key = PBKDF2(password, salt, dkLen=32)
        
    
    print(wallet_array)

    selectedChain = "sepolia"

    wb = get_wallet_balance(wallet_array[0], selectedChain)
    usdp = float(get_eth_price_usd("ethereum")) * float(wb)

    data = {
        "user_id": user_id,
        "addresses": wallet_array,
        "selected_address": wallet_array[0],
        "selected_chain": selectedChain,
        "balance": wb,
        "usd": "{:.2f}".format(usdp)
    }

    return render_template('dashboard.html', data=data)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return redirect(url_for('index'))
    
    password = request.form['password']
    user_data = users.find_one({"password": password})
    if user_data is None:
        session['error'] = 'Incorrect password'
        return redirect(url_for('index'))
    
    session['user_id'] = str(user_data['_id'])
    session['password'] = str(password)
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(port=5001, debug=True)
