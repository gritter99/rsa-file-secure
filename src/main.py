import hashlib
from oaep import oaepEncode, oaepDecode
from generateRsaKeys import generateRsaKeys
from generatePrime import generateLargePrime
from fileSign import signFile
from verifySignature import verifySignature

def rsaEncrypt(message, publicKey, hashFunc=hashlib.sha3_256):
    """
    Cifra uma mensagem usando RSA com padding OAEP.

    Args:
        message (bytes): Mensagem em claro.
        publicKey (tuple): Chave pública (e, n).
        hashFunc (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Cifra gerada em bytes.

    Raises:
        ValueError: Se a mensagem for muito longa após o padding.
    """
    e, n = publicKey
    nByteLength = (n.bit_length() + 7) // 8
    paddedMessage = oaepEncode(message, nByteLength, hashFunc)
    mInt = int.from_bytes(paddedMessage, byteorder="big")
    if mInt >= n:
        raise ValueError("Mensagem muito longa após o padding OAEP.")
    cInt = pow(mInt, e, n)
    return cInt.to_bytes((n.bit_length() + 7) // 8, byteorder="big")

def rsaDecrypt(ciphertext, privateKey, hashFunc=hashlib.sha3_256):
    """
    Decifra uma mensagem usando RSA com padding OAEP.

    Args:
        ciphertext (bytes): Cifra gerada.
        privateKey (tuple): Chave privada (d, n).
        hashFunc (function): Função de hash (padrão: SHA3-256).

    Returns:
        bytes: Mensagem original decifrada.

    Raises:
        ValueError: Se o ciphertext for inválido ou o OAEP falhar.
    """
    d, n = privateKey
    nByteLength = (n.bit_length() + 7) // 8
    cInt = int.from_bytes(ciphertext, byteorder="big")
    if cInt >= n:
        raise ValueError("Ciphertext inválido.")
    mInt = pow(cInt, d, n)
    paddedMessage = mInt.to_bytes(nByteLength, byteorder="big")
    return oaepDecode(paddedMessage, nByteLength, hashFunc)

if __name__ == '__main__':
    # destinatário
    p = generateLargePrime(bits=1024, k=5)
    q = generateLargePrime(bits=1024, k=5)
    public_key_dest, private_key_dest = generateRsaKeys(p, q)

    print('Número primo p gerado:', p)
    print('\n')
    print('Número primo q gerado:', q)
    print('\n')
    print('Chave pública gerada:', public_key_dest)
    print('\n')
    print('Chave privada gerada:', private_key_dest)
    print('\n')

    # remetente
    p_rem = generateLargePrime(bits=1024, k=5)
    q_rem = generateLargePrime(bits=1024, k=5)
    public_key_rem, private_key_rem = generateRsaKeys(p_rem, q_rem)

    # remetente abre documento, cifra com a chave publica do destinatário para garantir integridade
    with open("confidential.txt", "rb") as file:
        document = file.read()
    ciphertext = rsaEncrypt(document, public_key_dest)
    print('RSA encriptado:', ciphertext)
    print('\n')
    
    # remetente assina o arquivo para garantir autenticidade
    signature = signFile("confidential.txt", private_key_rem)
    print('Assinatura:', signature)
    print('\n')

    # destinatario decifra o arquivo com sua chave privada (confidencialidade):
    decrypted_doc = rsaDecrypt(ciphertext, private_key_dest)
    with open("decrypted_confidential.txt", "wb") as file:
        file.write(decrypted_doc)

    # destinatário verifica a assinatura para validar a integridade
    is_valid = verifySignature("decrypted_confidential.txt", signature, public_key_rem)
    print("Assinatura válida?" , is_valid)