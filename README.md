# CSE127: Introduction to Computer Security Homework 6

Project Overview: The goal of this assignment is to gain hands-on experience with password cracking. Two types of passwords need to be cracked: unsalted vs salted. The following rules were used to dictate password formats used:

	1. An English word as the password

	2. A string of up to 8 digits as the password

	3. An English word followed by some digits, together no more than 10 characters

	4. An English word but change some letters to uppercase and change some letters to other symbols

	5. Concatenate two English words together

A dictionary word list is provided in words.txt

Letter replacements are described as follows: a -> @, b -> 8, c -> (, f -> #, g -> 9, i,l -> 1, o -> 0, s -> $

The password hashing function works by computing the MD5 hash of the input.
