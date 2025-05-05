def diffie_hellman():
    print("=== Diffie-Hellman Key Exchange ===")

    # Input: a large prime number (p) and a primitive root modulo p (g)
    p = int(input("Enter a large prime number (p): "))
    g = int(input("Enter a primitive root modulo p (g): "))

    # Each user selects a private key (kept secret)
    a = int(input("User A, enter your private key (a): "))
    b = int(input("User B, enter your private key (b): "))

    # Each user computes their public key to share: A = g^a mod p, B = g^b mod p
    A = pow(g, a, p)  # User A's public key
    B = pow(g, b, p)  # User B's public key

    print(f"User A sends public key: {A}")
    print(f"User B sends public key: {B}")

    # Each user computes the shared secret key using the other’s public key
    shared_key_a = pow(B, a, p)  # User A computes (B^a) mod p
    shared_key_b = pow(A, b, p)  # User B computes (A^b) mod p

    print(f"User A computes shared key: {shared_key_a}")
    print(f"User B computes shared key: {shared_key_b}")

    # Check if both users arrived at the same shared secret
    if shared_key_a == shared_key_b:
        print(f"\nShared secret established successfully! Key: {shared_key_a}")
    else:
        print("\nError: Keys do not match.")  # This should not happen in correct implementation

# Call the function to run the key exchange
diffie_hellman()
