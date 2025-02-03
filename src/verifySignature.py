import base64
from fileSign import computeFileHash

def decodeSignature(signatureB64, nByteLength):
    """
    Decodifica a assinatura de Base64 para inteiro.

    Args:
        signatureB64 (str): Assinatura em Base64.
        nByteLength (int): Tamanho da chave RSA em bytes.

    Returns:
        int: Assinatura como inteiro.
    """
    signatureBytes = base64.b64decode(signatureB64)
    return int.from_bytes(signatureBytes, byteorder="big")

def verifySignature(filePath, signatureB64, publicKey):
    """
    Verifica se a assinatura corresponde ao hash do arquivo.

    Args:
        filePath (str): Caminho do arquivo.
        signatureB64 (str): Assinatura em Base64.
        publicKey (tuple): Chave pública (e, n).

    Returns:
        bool: True se a assinatura é válida, False caso contrário.
    """
    e, n = publicKey
    nByteLength = (n.bit_length() + 7) // 8
    
    signatureInt = decodeSignature(signatureB64, nByteLength)
    decryptedHashInt = pow(signatureInt, e, n)
    decryptedHash = decryptedHashInt.to_bytes(32, byteorder="big")  # SHA3-256 tem 32 bytes

    currentHash = computeFileHash(filePath)
    
    return decryptedHash == currentHash