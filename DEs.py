# Perform permutation on input bits using a given permutation table
def permute(input_bits, permutation_table):
    """Permute the input bits according to the permutation table."""
    return [input_bits[i - 1] for i in permutation_table]

# Perform circular left shift on a list of bits
def left_shift(bits, n_shifts):
    """Perform a circular left shift on the bits."""
    return bits[n_shifts:] + bits[:n_shifts]

# Perform bitwise XOR between two bit arrays
def xor(bits1, bits2):
    """Perform XOR operation on two bit arrays."""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

# Apply S-box substitution using a 2x2 bit input and a 4x4 S-box
def s_box_substitution(bits, s_box):
    """Perform S-box substitution."""
    row = bits[0] * 2 + bits[3]  # First and last bits define row
    col = bits[1] * 2 + bits[2]  # Middle two bits define column
    val = s_box[row][col]        # Look up value in S-box
    return [val // 2, val % 2]   # Return 2-bit result

# Generate two subkeys (K1 and K2) from a 10-bit master key
def generate_subkeys(key):
    """Generate two subkeys from the 10-bit master key."""
    # Step 1: Apply initial permutation P10
    p10_table = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    key = permute(key, p10_table)
    
    # Step 2: Split into two 5-bit halves
    left = key[:5]
    right = key[5:]
    
    # Step 3: Left shift both halves by 1 for K1
    left = left_shift(left, 1)
    right = left_shift(right, 1)
    
    # Step 4: Combine halves and apply P8 to generate K1
    p8_table = [6, 3, 7, 4, 8, 5, 10, 9]
    k1 = permute(left + right, p8_table)
    
    # Step 5: Left shift both halves by 2 more positions for K2
    left = left_shift(left, 2)
    right = left_shift(right, 2)
    
    # Step 6: Combine and apply P8 again to generate K2
    k2 = permute(left + right, p8_table)
    
    return k1, k2

# Feistel function used in each encryption/decryption round
def function_F(right_half, subkey):
    """Apply the Feistel function F to the right half."""
    # Step 1: Expand and permute 4-bit input to 8 bits
    ep_table = [4, 1, 2, 3, 2, 3, 4, 1]
    expanded = permute(right_half, ep_table)
    
    # Step 2: XOR with subkey
    xored = xor(expanded, subkey)
    
    # Step 3: Split result into two 4-bit blocks
    left = xored[:4]
    right = xored[4:]
    
    # Step 4: Apply S-box substitutions
    s0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]
    s1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ]
    left_result = s_box_substitution(left, s0)
    right_result = s_box_substitution(right, s1)
    
    # Step 5: Combine S-box outputs and apply permutation P4
    combined = left_result + right_result
    p4_table = [2, 4, 3, 1]
    return permute(combined, p4_table)

# Encrypt an 8-bit plaintext block using the S-DES algorithm
def encrypt_block(plaintext, key):
    """Encrypt an 8-bit block using S-DES."""
    # Step 1: Generate subkeys K1 and K2
    k1, k2 = generate_subkeys(key)
    
    # Step 2: Apply initial permutation (IP)
    ip_table = [2, 6, 3, 1, 4, 8, 5, 7]
    plaintext = permute(plaintext, ip_table)
    
    # Step 3: Split into left and right halves
    left = plaintext[:4]
    right = plaintext[4:]
    
    # Step 4: First round with K1
    new_right = xor(left, function_F(right, k1))
    left = right
    right = new_right
    
    # Step 5: Second round with K2
    new_right = xor(left, function_F(right, k2))
    left = right
    right = new_right
    
    # Step 6: Combine halves in switched order
    combined = right + left
    
    # Step 7: Apply inverse initial permutation (IP^-1)
    ip_inverse_table = [4, 1, 3, 5, 7, 2, 8, 6]
    return permute(combined, ip_inverse_table)

# Decrypt an 8-bit ciphertext block using S-DES (same structure as encryption but with reversed key order)
def decrypt_block(ciphertext, key):
    """Decrypt an 8-bit block using S-DES."""
    # Step 1: Generate subkeys
    k1, k2 = generate_subkeys(key)
    
    # Step 2: Apply initial permutation
    ip_table = [2, 6, 3, 1, 4, 8, 5, 7]
    ciphertext = permute(ciphertext, ip_table)
    
    # Step 3: Split into halves
    left = ciphertext[:4]
    right = ciphertext[4:]
    
    # Step 4: First round with K2 (reversed order)
    new_right = xor(left, function_F(right, k2))
    left = right
    right = new_right
    
    # Step 5: Second round with K1
    new_right = xor(left, function_F(right, k1))
    left = right
    right = new_right
    
    # Step 6: Switch and apply inverse permutation
    combined = right + left
    ip_inverse_table = [4, 1, 3, 5, 7, 2, 8, 6]
    return permute(combined, ip_inverse_table)

# Utility to convert bit array to integer
def bits_to_int(bits):
    """Convert a bit array to an integer."""
    return sum(bit << i for i, bit in enumerate(reversed(bits)))

# Utility to convert integer to bit array of fixed length
def int_to_bits(n, length):
    """Convert an integer to a bit array of specified length."""
    return [(n >> i) & 1 for i in range(length-1, -1, -1)]

# Run test cases to demonstrate encryption and decryption
def run_test_cases():
    print("S-DES Test Cases:")
    
    # Test case 1
    key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    plaintext = [1, 0, 0, 1, 0, 1, 1, 1]
    ciphertext = encrypt_block(plaintext, key)
    decrypted = decrypt_block(ciphertext, key)
    
    print(f"Key (binary): {key}")
    print(f"Key (decimal): {bits_to_int(key)}")
    print(f"Plaintext (binary): {plaintext}")
    print(f"Plaintext (decimal): {bits_to_int(plaintext)}")
    print(f"Ciphertext (binary): {ciphertext}")
    print(f"Ciphertext (decimal): {bits_to_int(ciphertext)}")
    print(f"Decrypted (binary): {decrypted}")
    print(f"Decrypted (decimal): {bits_to_int(decrypted)}")
    print(f"Decryption successful: {plaintext == decrypted}")
    
    # Test case 2
    key = [0, 1, 1, 1, 1, 0, 0, 1, 1, 0]
    plaintext = [0, 0, 0, 0, 1, 1, 1, 1]
    ciphertext = encrypt_block(plaintext, key)
    decrypted = decrypt_block(ciphertext, key)
    
    print("\nTest case 2:")
    print(f"Key (binary): {key}")
    print(f"Key (decimal): {bits_to_int(key)}")
    print(f"Plaintext (binary): {plaintext}")
    print(f"Plaintext (decimal): {bits_to_int(plaintext)}")
    print(f"Ciphertext (binary): {ciphertext}")
    print(f"Ciphertext (decimal): {bits_to_int(ciphertext)}")
    print(f"Decrypted (binary): {decrypted}")
    print(f"Decrypted (decimal): {bits_to_int(decrypted)}")
    print(f"Decryption successful: {plaintext == decrypted}")

# Entry point
if __name__ == "__main__":
    run_test_cases()
