# Secure Message Vault CTF Challenge

Bem-vindo ao desafio **Secure Message Vault**! Seu objetivo é descriptografar a mensagem sem conhecer a senha original.

## Visão Geral

O programa `vault` utiliza:

- ChaCha20-Poly1305 (IETF) para cifrar e autenticar
- Argon2id (modo INTERACTIVE) para derivar a chave da senha
- Formato de saída em hex, com header contendo:
  1. **Versão** (1 byte)
  2. **Salt** (16 bytes)
  3. **Nonce** (12 bytes)
  4. **Timestamp** (8 bytes, little-endian)
  5. **Ciphertext + MAC**

O binário espera argumentos:

```bash
./vault -e -k <senha> -m "<mensagem>"   # encripta
./vault -d -k <senha> -h <hex>          # decripta
./vault -t #Teste
```

## Dicas

- O **test vector** interno pode revelar detalhes úteis…
- Atenção à **ordem de bytes** do timestamp: little-endian.
- Salt e nonce têm **tamanhos fixos** (16 e 12 bytes).
- O byte de **versão** (`0x04`) aparece antes de tudo.
- Mensagens de erro seguem padrões claros (lembre-se de capturar stderr).
- O esquema de hashing usa **OPSLIMIT\_INTERACTIVE** — ajustá-lo pode acelerar brute‑force.
- Formato hex espera **pares de dígitos**: uma letra a mais ou a menos falha.
- A biblioteca não zera todos os buffers: patters repetidos podem vazar.
- O timestamp tem tolerância finita (futuro e passado) — explorar datas fora do intervalo.
- Você tem acesso total ao codigo fonte, podendo fazer o que quiser. Esta contido no cipher.c

## Como Submeter

1. Decripte o hex fornecido.
2. Revele o texto original.
3. Envie como resposta no portal.

## Mensagem Cifrada

Esta é a mensagem que você deve descriptografar:

```
048c72e5cfe4d34f633afb9c02f69927d7f8d1bf3c111dc2aba0470e8f04cd616800000000c5da021cc8c91ea92dcc1f6b6eec8ae4a4b0130b498ecda4791c314c0de81a1ed265ecf734f6140238f624be13b9178a4a6f66beff24caddaae945f66dd3f430f0a44906b495793b93b5e353c96612858a919ef92997e8eab5a3add21f319686e14a145bc39f70db19d879952d9b8730e6061c7bf3
```

Boa sorte e bom hacking! 😉

