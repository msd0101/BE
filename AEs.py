# Simplified AES (S-AES) Implementation
# A pedagogical version of AES with 16-bit block size and 16-bit key size

# ===== S-AES CONSTANTS =====

# S-box for substitution (4x4 lookup table)
# Used in SubBytes step for non-linear substitution
SBOX = [
    [0x9, 0x4, 0xA, 0xB],  # Row 0
    [0xD, 0x1, 0x8, 0x5],  # Row 1
    [0x6, 0x2, 0x0, 0x3],  # Row 2
    [0xC, 0xE, 0xF, 0x7]   # Row 3
]

# Inverse S-box for decryption (4x4 lookup table)
# Used in InvSubBytes step to reverse substitution
INV_SBOX = [
    [0xA, 0x5, 0x9, 0xB],  # Row 0
    [0x1, 0x7, 0x8, 0xF],  # Row 1
    [0x6, 0x0, 0x2, 0x3],  # Row 2
    [0xC, 0x4, 0xD, 0xE]   # Row 3
]

# MixColumns constant matrix (2x2)
# Used to mix columns during encryption
MIX_COL_MATRIX = [
    [1, 4],  # First row
    [4, 1]   # Second row
]

# Inverse MixColumns constant matrix (2x2)
# Used to reverse column mixing during decryption
INV_MIX_COL_MATRIX = [
    [9, 2],  # First row
    [2, 9]   # Second row
]

# ===== GALOIS FIELD OPERATIONS =====

def gf_mult(a, b):
    """
    Galois Field Multiplication in GF(2^4) with irreducible polynomial x^4 + x + 1.
    
    Args:
        a, b: 4-bit numbers to multiply
        
    Returns:
        Product in GF(2^4) (4-bit result)
    """
    product = 0
    for i in range(4):  # For each bit in b
        if (b & 1) == 1:  # If LSB of b is 1
            product ^= a  # Add (XOR) a to product
        high_bit = a & 0x8  # Check if a will overflow when shifted
        a <<= 1  # Multiply a by x
        if high_bit == 0x8:  # If overflow would occur
            a ^= 0x13  # Reduce using x^4 + x + 1 = 0b10011
        b >>= 1  # Move to next bit of b
    return product & 0xF  # Ensure 4-bit result

# ===== KEY EXPANSION =====

def key_expansion(key):
    """
    Expand the 16-bit key into two 16-bit round keys.
    
    Args:
        key: 16-bit master key
        
    Returns:
        tuple: (round_key1, round_key2) - two 16-bit round keys
    """
    w = [0] * 6  # Key expansion words (6 bytes total)
    
    # Split the 16-bit key into two 8-bit words
    w[0] = (key >> 8) & 0xFF  # First byte
    w[1] = key & 0xFF         # Second byte
    
    # Round constants for key expansion
    rcon1 = 0x80  # First round constant: 10000000
    rcon2 = 0x30  # Second round constant: 00110000
    
    # Generate w[2] and w[3] (first round key)
    rot_w1 = ((w[1] << 4) & 0xF0) | ((w[1] >> 4) & 0x0F)  # Rotate nibbles
    sub_rot_w1 = substitute_word(rot_w1)  # Apply S-box to each nibble
    w[2] = w[0] ^ rcon1 ^ sub_rot_w1  # XOR with first word and rcon
    w[3] = w[2] ^ w[1]  # XOR with previous word
    
    # Generate w[4] and w[5] (second round key)
    rot_w3 = ((w[3] << 4) & 0xF0) | ((w[3] >> 4) & 0x0F)  # Rotate nibbles
    sub_rot_w3 = substitute_word(rot_w3)  # Apply S-box to each nibble
    w[4] = w[2] ^ rcon2 ^ sub_rot_w3  # XOR with previous word and rcon
    w[5] = w[4] ^ w[3]  # XOR with previous word
    
    # Combine bytes to form 16-bit round keys
    round_key1 = (w[2] << 8) | w[3]  # First round key
    round_key2 = (w[4] << 8) | w[5]  # Second round key
    
    return round_key1, round_key2

def substitute_word(word):
    """
    Apply S-box substitution to each nibble in a byte.
    
    Args:
        word: 8-bit input value
        
    Returns:
        8-bit result after S-box substitution
    """
    high_nibble = (word >> 4) & 0xF  # Upper 4 bits
    low_nibble = word & 0xF          # Lower 4 bits
    
    # Lookup substitution for high nibble
    row_h, col_h = high_nibble >> 2, high_nibble & 0x3
    sub_high = SBOX[row_h][col_h]
    
    # Lookup substitution for low nibble
    row_l, col_l = low_nibble >> 2, low_nibble & 0x3
    sub_low = SBOX[row_l][col_l]
    
    return (sub_high << 4) | sub_low  # Combine substituted nibbles

# ===== ENCRYPTION FUNCTIONS =====

def add_round_key(state, round_key):
    """
    XOR the state with the round key (simple bitwise XOR).
    
    Args:
        state: 16-bit current state
        round_key: 16-bit round key
        
    Returns:
        16-bit result after XOR with round key
    """
    return state ^ round_key

def substitute_bytes(state):
    """
    Apply S-box substitution to each nibble in the state.
    
    Args:
        state: 16-bit current state
        
    Returns:
        16-bit result after S-box substitution
    """
    result = 0
    for i in range(4):  # Process 4 nibbles (16 bits total)
        nibble = (state >> (12 - 4*i)) & 0xF  # Extract each nibble
        row, col = nibble >> 2, nibble & 0x3  # Determine S-box row/col
        sub_nibble = SBOX[row][col]           # Get substitution
        result |= (sub_nibble << (12 - 4*i))  # Place back in result
    return result

def inverse_substitute_bytes(state):
    """
    Apply inverse S-box substitution to each nibble in the state.
    
    Args:
        state: 16-bit current state
        
    Returns:
        16-bit result after inverse S-box substitution
    """
    result = 0
    for i in range(4):  # Process 4 nibbles
        nibble = (state >> (12 - 4*i)) & 0xF  # Extract nibble
        row, col = nibble >> 2, nibble & 0x3  # Determine inverse S-box row/col
        sub_nibble = INV_SBOX[row][col]       # Get inverse substitution
        result |= (sub_nibble << (12 - 4*i))  # Place back in result
    return result

def shift_rows(state):
    """
    Perform the ShiftRows step (swap middle nibbles).
    
    Args:
        state: 16-bit current state
        
    Returns:
        16-bit result after shifting rows
    """
    # Extract the 4 nibbles (each 4 bits)
    n0 = (state >> 12) & 0xF  # First nibble (unchanged)
    n1 = (state >> 8) & 0xF   # Second nibble (swapped with n3)
    n2 = (state >> 4) & 0xF   # Third nibble (unchanged)
    n3 = state & 0xF          # Fourth nibble (swapped with n1)
    
    # Shift the rows (swap n1 and n3)
    return (n0 << 12) | (n3 << 8) | (n2 << 4) | n1

def mix_columns(state):
    """
    Perform the MixColumns step (matrix multiplication in GF(2^4)).
    
    Args:
        state: 16-bit current state
        
    Returns:
        16-bit result after mixing columns
    """
    # Extract the two columns (each 8 bits)
    c0 = (state >> 8) & 0xFF  # First column
    c1 = state & 0xFF         # Second column
    
    # Extract the 4 elements (each 4 bits)
    s00 = (c0 >> 4) & 0xF  # First element, first column
    s10 = c0 & 0xF         # Second element, first column
    s01 = (c1 >> 4) & 0xF  # First element, second column
    s11 = c1 & 0xF         # Second element, second column
    
    # Apply the MixColumns transformation (matrix multiplication)
    s00_new = gf_mult(MIX_COL_MATRIX[0][0], s00) ^ gf_mult(MIX_COL_MATRIX[0][1], s10)
    s10_new = gf_mult(MIX_COL_MATRIX[1][0], s00) ^ gf_mult(MIX_COL_MATRIX[1][1], s10)
    s01_new = gf_mult(MIX_COL_MATRIX[0][0], s01) ^ gf_mult(MIX_COL_MATRIX[0][1], s11)
    s11_new = gf_mult(MIX_COL_MATRIX[1][0], s01) ^ gf_mult(MIX_COL_MATRIX[1][1], s11)
    
    # Combine the new columns
    c0_new = (s00_new << 4) | s10_new  # New first column
    c1_new = (s01_new << 4) | s11_new  # New second column
    
    return (c0_new << 8) | c1_new  # Combine columns into 16-bit state

def inverse_mix_columns(state):
    """
    Perform the Inverse MixColumns step (reverse of MixColumns).
    
    Args:
        state: 16-bit current state
        
    Returns:
        16-bit result after inverse mixing columns
    """
    # Extract the two columns (each 8 bits)
    c0 = (state >> 8) & 0xFF  # First column
    c1 = state & 0xFF         # Second column
    
    # Extract the 4 elements (each 4 bits)
    s00 = (c0 >> 4) & 0xF  # First element, first column
    s10 = c0 & 0xF         # Second element, first column
    s01 = (c1 >> 4) & 0xF  # First element, second column
    s11 = c1 & 0xF         # Second element, second column
    
    # Apply the Inverse MixColumns transformation
    s00_new = gf_mult(INV_MIX_COL_MATRIX[0][0], s00) ^ gf_mult(INV_MIX_COL_MATRIX[0][1], s10)
    s10_new = gf_mult(INV_MIX_COL_MATRIX[1][0], s00) ^ gf_mult(INV_MIX_COL_MATRIX[1][1], s10)
    s01_new = gf_mult(INV_MIX_COL_MATRIX[0][0], s01) ^ gf_mult(INV_MIX_COL_MATRIX[0][1], s11)
    s11_new = gf_mult(INV_MIX_COL_MATRIX[1][0], s01) ^ gf_mult(INV_MIX_COL_MATRIX[1][1], s11)
    
    # Combine the new columns
    c0_new = (s00_new << 4) | s10_new  # New first column
    c1_new = (s01_new << 4) | s11_new  # New second column
    
    return (c0_new << 8) | c1_new  # Combine columns into 16-bit state

# ===== MAIN CIPHER FUNCTIONS =====

def encrypt(plaintext, key):
    """
    Encrypt 16-bit plaintext using 16-bit key.
    
    Args:
        plaintext: 16-bit plaintext to encrypt
        key: 16-bit encryption key
        
    Returns:
        16-bit ciphertext
    """
    # Generate round keys from master key
    round_key1, round_key2 = key_expansion(key)
    
    # Initial round (AddRoundKey with original key)
    state = add_round_key(plaintext, key)
    
    # Round 1
    state = substitute_bytes(state)  # Non-linear substitution
    state = shift_rows(state)       # Permutation
    state = mix_columns(state)      # Diffusion
    state = add_round_key(state, round_key1)  # XOR with round key
    
    # Round 2 (final round - no MixColumns)
    state = substitute_bytes(state)  # Non-linear substitution
    state = shift_rows(state)       # Permutation
    state = add_round_key(state, round_key2)  # XOR with round key
    
    return state

def decrypt(ciphertext, key):
    """
    Decrypt 16-bit ciphertext using 16-bit key.
    
    Args:
        ciphertext: 16-bit ciphertext to decrypt
        key: 16-bit decryption key
        
    Returns:
        16-bit plaintext
    """
    # Generate round keys from master key
    round_key1, round_key2 = key_expansion(key)
    
    # Initial round (reverse of final encryption round)
    state = add_round_key(ciphertext, round_key2)  # XOR with last round key
    state = shift_rows(state)                     # Inverse shift (same as forward)
    state = inverse_substitute_bytes(state)      # Inverse substitution
    
    # Round 1
    state = add_round_key(state, round_key1)      # XOR with first round key
    state = inverse_mix_columns(state)           # Inverse mix columns
    state = shift_rows(state)                    # Inverse shift (same as forward)
    state = inverse_substitute_bytes(state)      # Inverse substitution
    
    # Final round (reverse of initial encryption round)
    state = add_round_key(state, key)  # XOR with original key
    
    return state

# ===== TESTING =====

def run_test_cases():
    """Run test cases to verify S-AES implementation."""
    print("S-AES Test Cases:")
    
    # Test case 1
    key = 0xABCD
    plaintext = 0x1234
    
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    
    print(f"Key: 0x{key:04X}")
    print(f"Plaintext: 0x{plaintext:04X}")
    print(f"Ciphertext: 0x{ciphertext:04X}")
    print(f"Decrypted: 0x{decrypted:04X}")
    print(f"Decryption successful: {plaintext == decrypted}")
    
    # Test case 2
    key = 0x4AF5
    plaintext = 0xB1D3
    
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    
    print("\nTest case 2:")
    print(f"Key: 0x{key:04X}")
    print(f"Plaintext: 0x{plaintext:04X}")
    print(f"Ciphertext: 0x{ciphertext:04X}")
    print(f"Decrypted: 0x{decrypted:04X}")
    print(f"Decryption successful: {plaintext == decrypted}")

if __name__ == "__main__":
    run_test_cases()