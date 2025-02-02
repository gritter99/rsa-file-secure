import hashlib
from oaep import oaepEncode, oaepDecode
from generateRsaKeys import generateRsaKeys
from generatePrime import generateLargePrime

def rsa_encrypt(message, public_key, hash_func=hashlib.sha3_256):
    """
    Cifra uma mensagem usando RSA com padding OAEP.

    Args:
        message (bytes): Mensagem em claro.
        public_key (tuple): Chave pública (e, n).
        hash_func (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Cifra gerada em bytes.

    Raises:
        ValueError: Se a mensagem for muito longa após o padding.
    """
    e, n = public_key
    n_byte_length = (n.bit_length() + 7) // 8
    padded_message = oaepEncode(message, n_byte_length, hash_func)
    m_int = int.from_bytes(padded_message, byteorder="big")
    if m_int >= n:
        raise ValueError("Mensagem muito longa após o padding OAEP.")
    c_int = pow(m_int, e, n)
    return c_int.to_bytes((n.bit_length() + 7) // 8, byteorder="big")

def rsa_decrypt(ciphertext, private_key, hash_func=hashlib.sha3_256):
    """
    Decifra uma mensagem usando RSA com padding OAEP.

    Args:
        ciphertext (bytes): Cifra gerada.
        private_key (tuple): Chave privada (d, n).
        hash_func (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Mensagem original decifrada.

    Raises:
        ValueError: Se o ciphertext for inválido ou o OAEP falhar.
    """
    d, n = private_key
    n_byte_length = (n.bit_length() + 7) // 8
    c_int = int.from_bytes(ciphertext, byteorder="big")
    if c_int >= n:
        raise ValueError("Ciphertext inválido.")
    m_int = pow(c_int, d, n)
    padded_message = m_int.to_bytes(n_byte_length, byteorder="big")
    return oaepDecode(padded_message, n_byte_length, hash_func)

if __name__ == '__main__':
    p = generateLargePrime()
    q = generateLargePrime()
    public_key, private_key = generateRsaKeys(p, q)

    message = b"senha importante"
    ciphertext = rsa_encrypt(message, public_key)

    print('Mensagem cifrada:', ciphertext)

    decrypted_message = rsa_decrypt(ciphertext, private_key)
    print("Mensagem decifrada:", decrypted_message.decode())