#!/usr/bin/env python3
"""
Analyze randomness of ATSHA204A output data.
Tests for basic entropy, patterns, and statistical properties.

Convert the binary key to a suitable hex format:

$ hexdump -v -e '32/1 "%02x " "\n"' ez.key > ez.hex
$ python3 testrand.py ez.hex

"""

import sys
from collections import Counter
import math

def shannon_entropy(data):
    """Calculate Shannon entropy (bits per byte)"""
    if not data:
        return 0
    
    counter = Counter(data)
    length = len(data)
    
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def chi_square_test(data):
    """Chi-square test for uniform distribution"""
    if not data:
        return 0, 0
    
    counter = Counter(data)
    expected = len(data) / 256
    
    chi_square = 0
    for i in range(256):
        observed = counter.get(i, 0)
        chi_square += (observed - expected) ** 2 / expected
    
    # Chi-square critical value for 255 degrees of freedom at p=0.05 is ~293.25
    # At p=0.01 is ~310.46
    return chi_square, 293.25

def count_repeating_bytes(data):
    """Count consecutive repeated bytes"""
    if len(data) < 2:
        return 0
    
    repeats = 0
    for i in range(len(data) - 1):
        if data[i] == data[i + 1]:
            repeats += 1
    
    return repeats

def longest_run(data):
    """Find longest run of identical bytes"""
    if not data:
        return 0
    
    max_run = 1
    current_run = 1
    
    for i in range(1, len(data)):
        if data[i] == data[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    
    return max_run

def analyze_file(filename):
    """Analyze random data from file"""
    print(f"Analyzing: {filename}")
    print("=" * 70)
    
    all_bytes = []
    line_count = 0
    duplicate_lines = 0
    seen_lines = set()
    
    try:
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Parse hex bytes
                try:
                    hex_values = line.split()
                    if len(hex_values) != 32:
                        print(f"Warning: Line {line_num} has {len(hex_values)} bytes (expected 32)")
                        continue
                    
                    bytes_data = bytes([int(h, 16) for h in hex_values])
                    
                    # Check for duplicate lines
                    line_hash = bytes_data
                    if line_hash in seen_lines:
                        duplicate_lines += 1
                        print(f"⚠ WARNING: Line {line_num} is a duplicate!")
                    seen_lines.add(line_hash)
                    
                    all_bytes.extend(bytes_data)
                    line_count += 1
                    
                except ValueError as e:
                    print(f"Error parsing line {line_num}: {e}")
                    continue
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return
    
    if not all_bytes:
        print("No data to analyze")
        return
    
    # Run tests
    print(f"\nData Summary:")
    print(f"  Lines processed: {line_count}")
    print(f"  Total bytes: {len(all_bytes)}")
    print(f"  Duplicate lines: {duplicate_lines}")
    
    print(f"\nEntropy Analysis:")
    entropy = shannon_entropy(all_bytes)
    print(f"  Shannon entropy: {entropy:.4f} bits/byte")
    print(f"  Ideal entropy: 8.0000 bits/byte")
    print(f"  Quality: ", end="")
    if entropy > 7.99:
        print("✓ Excellent")
    elif entropy > 7.95:
        print("✓ Good")
    elif entropy > 7.90:
        print("⚠ Acceptable")
    else:
        print("✗ Poor - NOT random!")
    
    print(f"\nDistribution Test:")
    chi_sq, critical = chi_square_test(all_bytes)
    print(f"  Chi-square value: {chi_sq:.2f}")
    print(f"  Critical value (p=0.05): {critical:.2f}")
    print(f"  Result: ", end="")
    if chi_sq < critical:
        print("✓ Passes (uniform distribution)")
    else:
        print("✗ Fails (non-uniform distribution)")
    
    print(f"\nPattern Analysis:")
    repeats = count_repeating_bytes(all_bytes)
    expected_repeats = len(all_bytes) / 256  # Expected for random data
    print(f"  Consecutive repeats: {repeats}")
    print(f"  Expected (random): ~{expected_repeats:.1f}")
    print(f"  Ratio: {repeats / expected_repeats:.2f}x")
    
    longest = longest_run(all_bytes)
    print(f"  Longest run: {longest} bytes")
    if longest > 5:
        print(f"  ⚠ WARNING: Long run detected")
    
    # Byte frequency analysis
    counter = Counter(all_bytes)
    most_common = counter.most_common(3)
    least_common = counter.most_common()[-3:]
    
    print(f"\nByte Frequency:")
    print(f"  Most common: {most_common[0][0]:02X} appears {most_common[0][1]} times")
    print(f"  Least common: {least_common[0][0]:02X} appears {least_common[0][1]} times")
    print(f"  Range: {most_common[0][1] - least_common[0][1]} (smaller is better)")
    
    print(f"\nOverall Assessment:")
    issues = []
    if entropy < 7.95:
        issues.append("Low entropy")
    if chi_sq > critical:
        issues.append("Non-uniform distribution")
    if duplicate_lines > 0:
        issues.append(f"{duplicate_lines} duplicate line(s)")
    if longest > 5:
        issues.append(f"Long run of {longest} bytes")
    
    if not issues:
        print("  ✓ Data appears to be cryptographically random")
    else:
        print("  ✗ Issues detected:")
        for issue in issues:
            print(f"    - {issue}")
    
    print("=" * 70)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_random.py <filename>")
        print("\nExample file format (32 hex bytes per line):")
        print("07 83 03 84 3E 33 C7 AD E0 CA 2E 3C B9 9A 8D 4C 09 CF E6 FE 6C 91 CB 37 3D 60 1E F8 AE 38 B9 21")
        sys.exit(1)
    
    analyze_file(sys.argv[1])
