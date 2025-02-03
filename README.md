# rsa-file-secure

Trabalho de Segurança Computacional 

Gerador e verificador de assinaturas RSA em arquivos.


Passo a passo:

- [x] Implementar Miller-Rabin para gerar primos de 1024 bits

- [x] Gerar chaves RSA (p, q, n, e, d)

- [x] Implementar OAEP (padding e unpadding)

- [x] Implementar cifração/decifração RSA com OAEP

- [x] Implementar cálculo de hash SHA-3

- [x] Assinar o hash com chave privada e codificar em Base64

- [x] Implementar verificação: decodificar Base64, decifrar assinatura, comparar hashes

- [x] Testar as etapas (se tiver tempo)

- [x] Documentar tudo no PDF e preparar a apresentação

Exemplo prático (main.py):

Um usuário (Remetente) deseja enviar um documento confidencial ("confidential.txt") para um Destinatário de forma segura, garantindo:

1. Confidencialidade: Apenas o destinatário pode ler o documento.

2. Autenticidade: O destinatário pode confirmar que o documento foi enviado pelo remetente.

3. Integridade: O documento não foi alterado durante a transmissão.

Como rodar o projeto:

- Após clonar o repositório ou baixar a pasta do projeto, é necessário entrar na pasta src
- Comando para rodar os testes unitários (rsa e miller-rabin): python -m unittest tests.py -v
- Comando para rodar o exemplo prático: python main.py
