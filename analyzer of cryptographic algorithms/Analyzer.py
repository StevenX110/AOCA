import time
import hashlib
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto import Random


def analyze_algorithm(algorithm, plaintext):
    start_time = time.time()

    ciphertext = algorithm.encrypt(plaintext)

    decrypted_text = algorithm.decrypt(ciphertext)

    end_time = time.time()
    execution_time = end_time - start_time

    if decrypted_text == plaintext:
        correctness = "Correct"
    else:
        correctness = "Incorrect"

    hash_value = hashlib.sha256(ciphertext).hexdigest()

    print("Encryption algorithm: ", algorithm.name)
    print("Encryption time: ", execution_time, "seconds")
    print("Decryption correctness: ", correctness)
    print("Encrypted text hash: ", hash_value)
    print("----------------------------------------------")


def main():
    data = Random.new().read(1024)

    ciphers = [
        {'name': 'AES', 'cipher': AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')},
        {'name': 'DES', 'cipher': DES.new('abcdefgh', DES.MODE_CBC)},
        {'name': 'Blowfish', 'cipher': Blowfish.new('abcdefgh', Blowfish.MODE_CBC)}
    ]

    for cipher_info in ciphers:
        cipher = cipher_info['cipher']
        start_time = time.time()
        encrypted_data = cipher.encrypt(pad(data, cipher.block_size))
        end_time = time.time()
        print(f"{cipher_info['name']} encryption took {end_time - start_time} seconds")

    for cipher_info in ciphers:
        cipher = cipher_info['cipher']
        start_time = time.time()
        decrypted_data = unpad(cipher.decrypt(encrypted_data), cipher.block_size)
        end_time = time.time()
        print(f"{cipher_info['name']} decryption took {end_time - start_time} seconds")

    plaintext = "Text for encryption".encode()
    encryption_algorithm = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    encryption_algorithm.name = 'AES'

    analyze_algorithm(encryption_algorithm, plaintext)


if __name__ == "__main__":
    main()
