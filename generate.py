import random
import hashlib as hs

bip39_list = open("words.txt", "r").read().split(",") #split it and transform it into an array

words_list = [] #initialize private key words

#pick random 12 words, the loop will continue until the array contains 12 unique words.
while len(words_list) < 12:
    random_word = bip39_list[random.randint(0, 2048 - 1)] #pick a random word

    if random_word not in words_list: #check if the word is already in the array
        words_list.append(random_word)

mnemonic_code = ' '.join(words_list)

print(f"Mnemonic phrase: {mnemonic_code}") #DISPLAY

seed = hs.pbkdf2_hmac(
    'sha512', #sha function used
    mnemonic_code.encode(), #convert phrase to bytes
    b'mnemonic', #standard salt used across wallets
    2048 #BIP39 standard iterations
    )

print(f"Seed (hex): {seed.hex()}")

#NOT FINISHED YET
