from random import randint

from aes import encrypt, int_key_to_n_char_arr, decrypt

import hashlib


def n_bit_rand_int(n):
    '''
    :param n: a number of bits
    :return: a random integer with n binary bits
    '''
    result = 0
    for i in range(n):
        result |= randint(0, 1) << i
    return result


def to_powers_of_2(a):
    '''
    Converts a number to an array indicating which powers
    of 2 it contains. For use with modular exponentiation.

    ex. to_powers_of_2(11) => [0, 1, 3]
    :param a: the number to convert
    :return: an array where each value indicates a power of 2
    '''
    result = []
    while a > 0:
        result.append(a & 1)
        a = a // 2
    return [i for i in range(len(result)) if result[i] == 1]


def mod_exp(a, b, n):
    '''
    Efficiently computes a ^ b % n
    :param a: the base
    :param b: the exponent
    :param n: the base of the modulus
    :return: a ^ b % n
    '''
    exponents = to_powers_of_2(b)
    product = 1
    for i in exponents:
        cur = a
        # a * b mod n = (a mod n * b mod n) mod n
        for j in range(i):
            cur = (cur * cur) % n
        product = (product * cur) % n
    return product % n


class Communicator:
    '''
    Class that can securely send and receive messages to other communicators.
    '''
    def __init__(self):
        self.g = 2
        self.p = 2 * (1416461893 + 10 ** 500) + 1
        self.keys = {}
        self.private_key = None

    def send_message(self, message, recipient):
        self.generate_key(recipient)
        key = self.keys[recipient]
        encrypted_message = self.encrypt_message(message, key)
        message_hash = self.compute_hash(message)
        self.send_encrypted_message(encrypted_message, message_hash, recipient)

    def send_encrypted_message(self, encrypted_message, message_hash, recipient):
        recipient.receive_encrypted_message(encrypted_message, message_hash, self)

    def receive_encrypted_message(self, encrypted_message, message_hash, sender):
        key = self.keys[sender]
        decrypted_message = self.decrypt_message(encrypted_message, key)
        assert message_hash == self.compute_hash(decrypted_message)
        print('Message received and authenticated.')
        print('Message:', decrypted_message)

    @staticmethod
    def encrypt_message(message, key):
        return encrypt(message, int_key_to_n_char_arr(key))

    @staticmethod
    def compute_hash(message):
        '''
        Compute a hash function for a string message to use when authenticating
        :param message:
        :return:
        '''
        m = hashlib.sha512()
        m.update(message.encode('utf-8'))
        return m.digest()

    @staticmethod
    def decrypt_message(message, key):
        '''
        Decrypt a message
        :param message: the
        :param key:
        :return:
        '''
        return decrypt(message, int_key_to_n_char_arr(key))

    def generate_key(self, recipient, n=256):
        '''
        Generates a cryptographic key using the Diffie-Hellman-Merkle algorithm.
        Network communication is simulated with the receive functions.
        :param recipient: the communicator to send a message to
        :param n: the number of bits to use in the key
        :return: the shared key
        '''
        a = n_bit_rand_int(n)
        A = mod_exp(self.g, a, self.p)
        B = self.request_public_key(recipient, n)
        self.send_public_key(A, recipient)
        key = mod_exp(B, a, self.p)
        self.keys[recipient] = key
        return key

    def send_public_key(self, public_key, recipient):
        '''
        Replace with network code to make this code actually work for clients/servers
        :param public_key: the key to send
        :param recipient: the recipient that will use the key
        :return: None
        '''
        recipient.receive_public_key(public_key, self)

    @staticmethod
    def request_public_key(recipient, n):
        '''
        Asks the recipient for a public key
        :param recipient: the recipient to ask
        :param n: the number of bits in the desired key
        :return: the recipient's response (hopefully a key)
        '''
        return recipient.receive_public_key_request(n)

    def receive_public_key_request(self, n):
        '''
        On receiving a key request, generate a private key, then send a public key.
        :param n: the number of bits in the key
        :return: an n bit key
        '''
        b = n_bit_rand_int(n)
        B = mod_exp(self.g, b, self.p)
        self.private_key = b
        return B

    def receive_public_key(self, public_key, sender):
        '''
        Compute the shared secret when a public key is received
        :param public_key: the sent key used to compute the shared secret
        :param sender: the sender of the secret
        :return: None, but keep a record of the public key for the sender
        '''
        self.keys[sender] = mod_exp(public_key, self.private_key, self.p)


