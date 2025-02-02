import unittest
import hashlib
from generatePrime import generateLargePrime, isPrime
from generateRsaKeys import generateRsaKeys
from oaep import oaepDecode, oaepEncode

class Tests(unittest.TestCase):
    def testPrimeProperties(self):
        """
        Testa as propriedades de números primos por miller-rabin
        """
        # gerar primos
        p = generateLargePrime(bits=1024, k=5)
        q = generateLargePrime(bits=1024, k=5)
        
        # verificar se são inteiros
        self.assertIsInstance(p, int)
        self.assertIsInstance(q, int)
        
        # verificar tamanho em bits (1024 bits)
        self.assertEqual(p.bit_length(), 1024)
        self.assertEqual(q.bit_length(), 1024)
        
        # verificar se são ímpares
        self.assertNotEqual(p % 2, 0)
        self.assertNotEqual(q % 2, 0)
        
        # verificar primalidade com Miller-Rabin (k=5)
        self.assertTrue(isPrime(p, k=5))
        self.assertTrue(isPrime(q, k=5))
        
        # garantir que p e q são diferentes
        self.assertNotEqual(p, q)
    
    def testRsaGenerator(self):
        """
        Testa a geração de chaves RSA
        """
        # gerar primos e chaves
        p = generateLargePrime(bits=1024, k=5)
        q = generateLargePrime(bits=1024, k=5)
        public_key, private_key = generateRsaKeys(p, q)

        # extrair componentes das chaves
        e, n_public = public_key
        d, n_private = private_key

        self.assertEqual(n_public, n_private, "n deve ser o mesmo nas chaves pública e privada")

        self.assertLessEqual(n_public.bit_length(), 2048, "n deve ter 2048 bits")
        self.assertGreaterEqual(n_public.bit_length(), 2047, "n deve ter pelo menos 2047 bits")

        # e*d ≡ 1 mod φ(n)
        phi = (p - 1) * (q - 1)
        self.assertEqual((e * d) % phi, 1, "d deve ser o inverso modular de e mod φ(n)")

        # e = 65537 (valor padrão)
        self.assertEqual(e, 65537, "e deve ser 65537")

        # p e q são diferentes
        self.assertNotEqual(p, q, "p e q devem ser primos distintos")

    def testOaepEncodingDecoding(self):
        """
        Testa a codificação e decodificação OAEP com uma mensagem de exemplo
        """
        # Gerar chaves RSA para obter o tamanho de n em bytes
        p = generateLargePrime(bits=1024, k=5)
        q = generateLargePrime(bits=1024, k=5)
        public_key, _ = generateRsaKeys(p, q)
        n = public_key[1]
        n_byte_length = (n.bit_length() + 7) // 8  # Tamanho de n em bytes

        # Mensagem de teste
        message = b"Hello, OAEP!"
        
        # Codificar
        encoded_message = oaepEncode(message, n_byte_length)
        
        # Verificar tamanho do encoded_message (deve ser igual a n_byte_length)
        self.assertEqual(len(encoded_message), n_byte_length, "Tamanho do encoded_message incorreto.")
        
        # Decodificar
        decoded_message = oaepDecode(encoded_message, n_byte_length)
        
        # Verificar integridade da mensagem
        self.assertEqual(decoded_message, message, "A mensagem decodificada não coincide com a original.")

    def testOaepInvalidMessageLength(self):
        """
        Testa se o OAEP rejeita mensagens maiores que o tamanho máximo permitido
        """
        p = generateLargePrime(bits=1024, k=5)
        q = generateLargePrime(bits=1024, k=5)
        public_key, _ = generateRsaKeys(p, q)
        n = public_key[1]
        n_byte_length = (n.bit_length() + 7) // 8
        
        # Mensagem maior que o limite permitido
        max_length = n_byte_length - 2 * hashlib.sha3_256().digest_size - 2
        invalid_message = b"a" * (max_length + 1)
        
        # Deve lançar ValueError
        with self.assertRaises(ValueError):
            oaepEncode(invalid_message, n_byte_length)

if __name__ == '__main__':
    unittest.main()