import hashlib
import secrets

def mgf1(seed, mask_length, hash_func=hashlib.sha3_256):
    """
    Gera uma máscara de bytes usando o algoritmo MGF1.

    Args:
        seed (bytes): Semente para gerar a máscara.
        mask_length (int): Tamanho desejado da máscara em bytes.
        hash_func (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Máscara gerada.
    """
    mask = b""
    counter = 0
    while len(mask) < mask_length:
        counter_bytes = counter.to_bytes(4, "big")
        mask += hash_func(seed + counter_bytes).digest()
        counter += 1
    return mask[:mask_length]

def oaepEncode(message, n_byte_length, hash_func=hashlib.sha3_256):
    """
    Aplica padding OAEP a uma mensagem para cifração RSA.

    Args:
        message (bytes): Mensagem em claro.
        n_byte_length (int): Tamanho da chave RSA em bytes.
        hash_func (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Mensagem com padding OAEP.
    """
    max_message_length = n_byte_length - 2 * hash_func().digest_size - 2
    if len(message) > max_message_length:
        raise ValueError("Mensagem muito longa para o tamanho da chave RSA.")
    
    l_hash = hash_func(b"").digest()
    ps = b"\x00" * (max_message_length - len(message))
    db = l_hash + ps + b"\x01" + message
    seed = secrets.token_bytes(hash_func().digest_size)
    db_mask = mgf1(seed, n_byte_length - hash_func().digest_size - 1)
    masked_db = bytes([db[i] ^ db_mask[i] for i in range(len(db))])
    seed_mask = mgf1(masked_db, hash_func().digest_size)
    masked_seed = bytes([seed[i] ^ seed_mask[i] for i in range(len(seed))])
    return b"\x00" + masked_seed + masked_db

def oaepDecode(encoded_message, n_byte_length, hash_func=hashlib.sha3_256):
    """
    Remove o padding OAEP de uma mensagem cifrada.

    Args:
        encoded_message (bytes): Mensagem com padding OAEP.
        n_byte_length (int): Tamanho da chave RSA em bytes.
        hash_func (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Mensagem original.
    """
    l_hash = hash_func(b"").digest()
    hash_size = hash_func().digest_size
    
    masked_seed = encoded_message[1 : 1 + hash_size]
    masked_db = encoded_message[1 + hash_size :]
    seed_mask = mgf1(masked_db, hash_size)
    seed = bytes([masked_seed[i] ^ seed_mask[i] for i in range(hash_size)])
    db_mask = mgf1(seed, n_byte_length - hash_size - 1)
    db = bytes([masked_db[i] ^ db_mask[i] for i in range(len(masked_db))])
    
    l_hash_recovered = db[:hash_size]
    if l_hash != l_hash_recovered:
        raise ValueError("OAEP decoding falhou: hash inválido.")
    
    message_start = db.find(b"\x01", hash_size) + 1
    if message_start == 0:
        raise ValueError("OAEP decoding falhou: separador não encontrado.")
    
    return db[message_start:]