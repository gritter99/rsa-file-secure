def extendedGcd(a, b):
    """
    Calcula o máximo divisor comum (gcd) de 'a' e 'b' e retorna coeficientes para a combinação linear Bézout.

    Args:
        a (int): Primeiro número.
        b (int): Segundo número.

    Returns:
        tuple: (gcd, x, y), onde gcd = mdc(a, b) e x, y são coeficientes que satisfazem ax + by = gcd.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extendedGcd(b % a, a)
        return (gcd, y - (b // a) * x, x)
    
def generateRsaKeys(p, q):
    """
    Gera as chaves pública e privada RSA a partir dos primos 'p' e 'q'.

    Args:
        p (int): Número primo (gerado via Miller-Rabin).
        q (int): Número primo (gerado via Miller-Rabin).

    Returns:
        tuple: (public_key, private_key), onde:
            - public_key = (e, n)
            - private_key = (d, n)
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # expoente público padrão
    gcd, x, _ = extendedGcd(e, phi)
    if gcd != 1:
        raise ValueError("e e φ(n) não são coprimos. Escolha outros primos.")
    d = x % phi  # inverso modular de 'e mod φ(n)'
    return (e, n), (d, n)