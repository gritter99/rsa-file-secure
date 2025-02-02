import secrets

def generateOddCandidate(bits=1024):
    """
    Gera um número ímpar aleatório de tamanho especificado em bits.
    
    Args:
        bits (int): Tamanho desejado em bits (padrão: 1024).
    
    Returns:
        int: Número ímpar de 'bits' bits.
    """
    candidate = secrets.randbits(bits)
    candidate |= (1 << (bits - 1)) # para garantir que tenha sempre 'bits' bits (eliminar o caso que o bit mais significativo seja 0)
    candidate | 1  # para que o número seja ímpar
    return candidate

def decompose(n_minus_1):
    """
    Decompõe n-1 em d * 2^s, onde d é ímpar.
    
    Args:
        n_minus_1 (int): O valor n-1 (n é o candidato a primo).
    
    Returns:
        tuple: (d, s), onde d é ímpar e s é o expoente.
    """
    s = 0
    d = n_minus_1
    while d % 2 == 0:
        d //= 2
        s += 1
    return d, s

def millerRabinTest(n, a):
    """
    Realiza uma rodada do teste de Miller-Rabin para a base 'a'.
    
    Args:
        n (int): Candidato a primo.
        a (int): Base aleatória para o teste.
    
    Returns:
        bool: False se 'n' é composto, True se passa no teste para a base 'a'.
    """
    d, s = decompose(n - 1)
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def isPrime(n, k=5):
    """
    Verifica se 'n' é provavelmente primo usando o teste de Miller-Rabin com 'k' rodadas.
    
    Args:
        n (int): Número a ser testado.
        k (int): Número de rodadas de teste (padrão: 5).
    
    Returns:
        bool: True se 'n' passa em todas as rodadas, False caso contrário.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a entre 2 e n-2
        if not millerRabinTest(n, a):
            return False
    return True

def generateLargePrime(bits=1024, k=5):
    """
    Gera um número primo de 'bits' bits usando o teste de Miller-Rabin.
    
    Args:
        bits (int): Tamanho em bits (padrão: 1024).
        k (int): Número de rodadas de teste (padrão: 5).
    
    Returns:
        int: Número primo de 'bits' bits.
    """
    while True:
        candidate = generateOddCandidate(bits)
        if isPrime(candidate, k):
            return candidate