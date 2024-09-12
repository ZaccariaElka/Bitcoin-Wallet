import random
import hashlib as hs
import hmac
from ecdsa import SigningKey, SECP256k1

bip39_list = open("words.txt", "r").read().split("\n") #split it and transform it into an array

words_list = [] #initialize private key words

#pick random 12 words, the loop will continue until the array contains 12 unique words.
while len(words_list) < 12:
    random_word = random.choice(bip39_list) #pick a random word

    if random_word not in words_list: #check if the word is already in the array
        words_list.append(random_word)

mnemonic_code = ' '.join(words_list).strip()

print(f"Mnemonic phrase: {mnemonic_code}") #DISPLAY

seed = hs.pbkdf2_hmac(
    'sha512', #sha function used
    mnemonic_code.encode(), #convert phrase to bytes
    b'mnemonic', #standard salt used across wallets
    2048 #BIP39 standard iterations
    )

print(f"Seed (hex): {seed.hex()}") #DISPLAY

key = b"Bitcoin seed" #standard value
hmac_result = hmac.new(key, seed, hs.sha512).digest() #get digest bytes of the computed HMAC-SHA512

master_private_key = hmac_result[:32] #get the master private key (the first 32 bytes)
chain_code = hmac_result[32:] #get the chain code in case i will need child keys (the last 32 bytes)

print("---")
print(f"Master Private Key: {master_private_key.hex()}") #DISPLAY
print(f"Chain Code: {chain_code.hex()}") #DISPLAY

public_key = SigningKey.from_string(master_private_key, curve=SECP256k1).verifying_key
public_key_hex = public_key.to_string().hex()

print("---")
print(f"Public Key (hex): {public_key_hex}") #DISPLAY


#NOT FINISHED
