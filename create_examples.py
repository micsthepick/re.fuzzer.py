import struct
import os

if not os.path.exists('base_examples'):
    os.makedirs('base_examples')

with open('base_examples/aaa.example', 'wb') as f:
    f.write(struct.pack('2H', 1, 0) + b'aaa\0\0\0\0\0')

with open('base_examples/aaabbaaa.example', 'wb') as f:
    f.write(struct.pack('2H', 3, 1) + b'aaabbaaa')
