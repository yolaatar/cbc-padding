**Service - CBC Padding**

This project implements a Padding Oracle attack to exploit a vulnerability in systems using AES in CBC mode with PKCS#7 padding, as featured in the Root Me challenge "Service - CBC Padding".

Library Used
We utilize the Python implementation of the paddingoracle library available on GitHub:
https://github.com/mwielgoszewski/python-paddingoracle

Description
The program connects to the target server (challenge01.root-me.org on port 51014) and exploits the Padding Oracle vulnerability. It performs the following steps:

***1 - Connection and Communication***

Establishes a TCP connection to the server.
Sends modified versions of the ciphertext in hexadecimal format.

***2 - Oracle Exploitation***

The oracle method queries the server and detects whether the modified ciphertext produces a padding error.
Based on the server's response, the program deduces the intermediate values and progressively reconstructs the plaintext byte by byte.

***3 - Plaintext Recovery and Post-Processing***

Once the complete plaintext (including padding) is reassembled, a PKCS#7 unpadding function is used to remove the padding and reveal the original message.
