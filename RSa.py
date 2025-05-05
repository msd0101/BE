import random

def gcd(a, b):
    # Compute the Greatest Common Divisor (GCD) using the Euclidean algorithm
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    # Compute the modular inverse of 'a' modulo 'm'
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None  # Return None if modular inverse doesn't exist

def is_prime(num):
    # Check if a number is prime
    if num <= 1:
        return False
    for i in range(2, int(num**0.5)+1):
        if num % i == 0:
            return False
    return True

def generate_random_prime(start=100, end=300):
    # Generate a random prime number between start and end
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num

def generate_keys():
    # Generate RSA public and private keys
    p = generate_random_prime()  # First prime number
    q = generate_random_prime()  # Second prime number

    while q == p:
        q = generate_random_prime()  # Ensure p and q are distinct

    print(f"Randomly chosen primes:\np = {p}, q = {q}")

    n = p * q  # Compute n (modulus)
    phi = (p - 1) * (q - 1)  # Compute Euler's totient function φ(n)

    # Choose a public exponent e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    d = modinv(e, phi)  # Compute private exponent d

    return ((e, n), (d, n))  # Return public and private key pairs

def encrypt(plaintext, public_key):
    # Encrypt plaintext using the public key
    e, n = public_key
    cipher = [(ord(char) ** e) % n for char in plaintext]  # Encrypt each character
    return cipher

def decrypt(ciphertext, private_key):
    # Decrypt ciphertext using the private key
    d, n = private_key
    plain = [chr((char ** d) % n) for char in ciphertext]  # Decrypt each character
    return ''.join(plain)

def main():
    print("RSA Encryption/Decryption with Random Keys")

    public_key, private_key = generate_keys()  # Generate keys
    print("\nPublic Key:", public_key)
    print("Private Key:", private_key)

    message = input("\nEnter message to encrypt: ")  # Take user input
    encrypted = encrypt(message, public_key)  # Encrypt the message
    print("\nEncrypted:", encrypted)

    decrypted = decrypt(encrypted, private_key)  # Decrypt the message
    print("Decrypted:", decrypted)

if __name__ == "__main__":
    main()  # Run the RSA demo
