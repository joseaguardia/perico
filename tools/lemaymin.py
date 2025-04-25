#!/usr/bin/env python3

# Given a word as a parameter, it generates all combinations 
# of uppercase and lowercase letters, preserving other symbols.

import sys
from itertools import product

def generate_case_combinations(word):
    # For each character, create a tuple with (lowercase, uppercase) if it's a letter
    # Otherwise, just include the character as-is
    options = [(char.lower(), char.upper()) if char.isalpha() else (char,) for char in word]

    # Compute the Cartesian product of all character options
    combinations = product(*options)

    # Join each tuple into a string
    return [''.join(combo) for combo in combinations]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python lemaymin.py <word>")
        sys.exit(1)

    input_word = sys.argv[1]
    results = generate_case_combinations(input_word)

    for result in results:
        print(result)
