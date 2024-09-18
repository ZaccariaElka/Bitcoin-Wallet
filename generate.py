import random
import hashlib as hl
import hmac
from ecdsa import SigningKey, SECP256k1
import base58

words_count = 12 #Number of words i want to use
unique_words = True #Don't repeat words
seed_salt = b'mnemonic' #Suggested to keep it the same for compatibility

bip39_list = open("words.txt", "r").read().split("\n") #Split words in the text file
words_list = [] #Initiate Array of saved words

while len(words_list) < words_count: #Loop through the bip39 list and append them to the saved words array
    random_word = random.choice(bip39_list)

    if unique_words:
        if random_word not in words_list:
            words_list.append(random_word)
    else:
        words_list.append(random_word)

mnemonic_phrase = ' '.join(words_list).strip() #Convert Array to string
print(f"Mnemonic Phrase: {mnemonic_phrase}")

seed = hl.pbkdf2_hmac( #Compute the seed using the "Password-Based Key Derivation Function 2", Combining the salt to the mnemonic phrase and hashing 2048
    'sha512',
    mnemonic_phrase.encode(),
    seed_salt, 
    2048
    )
print(f"Seed: {seed.hex()}")

hmac_result = hmac.new(b"Bitcoin seed", seed, hl.sha512).digest() #Combining the seed to the fixed key "Bitcoin seed" and hashing.
master_private_key = hmac_result[:32] #First 32 bytes are the private keys used to deliver the public key and address
chain_code = hmac_result[32:] #Last 32 Bytes are the chain code to deliver child keys (mostly for safety against attackers)

print(f"Private Key: {master_private_key.hex()}")
print(f"Chain Code: {chain_code.hex()}")

public_key = SigningKey.from_string(master_private_key, curve=SECP256k1).verifying_key.to_string() #Computing the Public key using the elliptic curve "secp256k1"
print(f"Public Key: {public_key.hex()}")


#This is the process to deliver the adress from the public key, thats just how the process is so i cannot explain into details
hash_sha256= hl.sha256(public_key).digest() #Hash the public key (SHA-256)
print("SHA-256 Hash:", hash_sha256.hex())

hash_ripemd160 = hl.new('ripemd160', hash_sha256).digest() #Hash again (RIPEMD-160)
print("RIPEMD-160 Hash:", hash_ripemd160.hex())

mainnet = b'\x00' #Network version

mainnet_hash = mainnet + hash_ripemd160 #Add the hashed public key (SHA-256 then RIPEMD-160)
print("Mainnet Hash:", mainnet_hash.hex())

checksum = hl.sha256(hl.sha256(mainnet_hash).digest()).digest()[:4] #The first 4 bytes of the "Mainnet Hash" hashed twice (SHA-256) (It is mostly used to detect errors during the adress creation)
print("Checksum:", checksum.hex()) 

combined_hashes = mainnet_hash + checksum #Add the checksum to the "Mainnet Hash"
print("Mainnet Hash + Checksum):", combined_hashes.hex())

bitcoin_address = base58.b58encode(combined_hashes).decode('utf-8') #Encode hash in Base58 and make it more human Readable creating a Bitcoin adress
print("Bitcoin Address:", bitcoin_address)
