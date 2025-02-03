import base64
import hashlib

def computeFileHash(filePath, hashFunc=hashlib.sha3_256):
    """
    Calcula o hash SHA-3 de um arquivo.

    Args:
        filePath (str): Caminho do arquivo.
        hashFunc (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Hash do arquivo em bytes.
    """
    with open(filePath, "rb") as file:
        data = file.read()
    return hashFunc(data).digest()

def signHash(hashValue, privateKey):
    """
    Assina um hash usando a chave privada RSA.

    Args:
        hashValue (bytes): Hash a ser assinado.
        privateKey (tuple): Chave privada (d, n).

    Returns:
        int: Assinatura como inteiro.
    """
    d, n = privateKey
    hashInt = int.from_bytes(hashValue, byteorder="big")
    return pow(hashInt, d, n)

def encodeSignature(signatureInt, nByteLength):
    """
    Codifica a assinatura em Base64.

    Args:
        signatureInt (int): Assinatura gerada.
        nByteLength (int): Tamanho da chave RSA em bytes.

    Returns:
        str: Assinatura em Base64.
    """
    signatureBytes = signatureInt.to_bytes(nByteLength, byteorder="big")
    return base64.b64encode(signatureBytes).decode()

def signFile(filePath, privateKey):
    """
    Assina um arquivo digitalmente.

    Args:
        filePath (str): Caminho do arquivo.
        privateKey (tuple): Chave privada (d, n).

    Returns:
        str: Assinatura em Base64.
    """
    hashValue = computeFileHash(filePath)
    signatureInt = signHash(hashValue, privateKey)
    nByteLength = (privateKey[1].bit_length() + 7) // 8
    return encodeSignature(signatureInt, nByteLength)

