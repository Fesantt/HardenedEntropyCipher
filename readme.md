
# 🔐 HardenedEntropyCipher V3 (C Edition) - Cifra Não-Determinística com Entropia Embutida

## 📌 Sobre

A **HardenedEntropyCipher V3 (C Edition)** é uma cifra **experimental**, **não-determinística**, com **entropia embutida**, criada para um único propósito:  
👉 **Ser reversível e ao mesmo tempo impossível de gerar duas vezes o mesmo ciphertext com o mesmo plaintext e mesma senha.**

> ⚠️ **AVISO DE SANIDADE:**  
Este código não é FIPS, não é NIST, não é PCI-DSS…  
É um projeto de um dev paranoico com tempo livre, café e trauma de implementações determinísticas.

---

## 🎯 Características-Chave

| Recurso | Status |
|---|---|
| **Não-Determinística (output sempre diferente)** | ✅ |
| Entropia embutida via Salt + Nonce + Timestamp | ✅ |
| Proteção contra Replay (Timestamp obrigatório no header) | ✅ |
| Validação de senha com análise de entropia | ✅ |
| Derivação com Argon2id (interativo) | ✅ |
| Header autenticado via AEAD (Additional Data) | ✅ |
| Zeroização de buffers sensíveis | ✅ |
| Tamanho limitado (64KB por design) | ✅ |
| Hex-safe para transporte | ✅ |
| Anti-brute force de entrada e senhas fracas | ✅ |
| Dependência: **libsodium >= 1.0.16** | ✅ |

---

## 📐 Estrutura Interna do Payload (Layout Hex)

```
[1 byte Versão] +
[24 bytes Salt] +
[12 bytes Nonce] +
[8 bytes Timestamp] +
[Ciphertext + MAC (16 bytes)]
```

> **Obs:** Cada execução da cifra com a mesma senha e mesmo plaintext gera um output **diferente**.

---

## 🚀 Porque Não-Determinística é Tão Importante?

Na prática:  
Mesmo que o atacante saiba a senha **e** o texto original, ele **não consegue** prever ou reconstruir o ciphertext exato que foi gerado.  
O nível de entropia por execução aumenta exponencialmente o custo de ataques por comparação.

---

## 📈 Comparativo com Outras Cifras

| Recurso | AES-GCM | ChaCha20-Poly1305 | HardenedEntropyCipher V3 |
|---|---|---|---|
| Não-determinística por padrão | ❌ | ✅ | ✅ |
| Header com timestamp autenticado | ❌ | ❌ | ✅ |
| Entropia adicional embutida (salt + nonce + ts) | ❌ | ✅ | ✅ |
| Validação de senha antes de criptografar | ❌ | ❌ | ✅ |
| Output em HEX (para transporte seguro) | ❌ | ❌ | ✅ |
| Buffer zeroization | Opcional | Parcial | ✅ |
| Proteção anti-replay | ❌ | ❌ | ✅ |
| Performance | Alta | Alta | **Baixa (por design 😂)** |

---

## ✅ Casos de Uso (Para quem é louco o suficiente)

- 🔐 Proteger configs locais com segurança paranoia
- ✅ Evitar outputs idênticos de forma matemática
- ✅ Transportar dados por canais que só aceitam ASCII puro (por conta do HEX)
- ❌ Não é pra armazenamento de senhas (use Argon2 puro pra isso)

---

## 🧪 Benchmark no Mundo Real (Ryzen 5 / Ubuntu)

| Payload | Tempo Médio |
|---|---|
| 10 bytes | ~150 ms |
| 1KB | ~160 ms |
| 10KB | ~180 ms |

> **Obs:** Isso aqui é um tanque de guerra, não um foguete.

---

## 🛠️ Compilação

```bash
$ make
```
> Requer libsodium já instalada.

---

## 🎯 Exemplos de Uso

### Criptografar:

```bash
./v3 -e -k "SenhaF0rte!" -m "Meu Segredo"
```

### Decriptar:

```bash
./v3 -d -k "SenhaF0rte!" -h "<hex_cifrado>"
```

### Gerar Test Vector:

```bash
./v3 -t
```

```tests=== Cryptographic Test Vector ===
Password: SecureTestPassword123!@#
Message: This is a test message for cryptographic verification.
[2025-06-18 04:47:00] INFO: Message encrypted successfully
Encrypted (hex): 03a44d733268fe7103c75f520b70cab9326e59fa989c7c2e16379100b8148b526800000000b443d558d9e94d517e5376f308e9c02ec3c71c7e1f3b11903f00cfec10c3477948b229307ad6f59f27136d5fc82f29458518ed2b354ab4d9d6b04c1c321364721d2acfe9931d
[2025-06-18 04:47:00] INFO: Message decrypted successfully
Decrypted: This is a test message for cryptographic verification.
Test: PASSED
================================
santt@Santt-pc:~/Área de trabalho/cript$ ./v11 -t
=== Cryptographic Test Vector ===
Password: SecureTestPassword123!@#
Message: This is a test message for cryptographic verification.
[2025-06-18 04:47:05] INFO: Message encrypted successfully
Encrypted (hex): 0340e2986f17925b9ab111e0ae7d61ada63a0e8038b36d6ac794663fbb198b526800000000b67942a5e7087be406911225bcbec2ab97265dfb77c04c80657235fd4289f6f2c99e41c57d91c435b746a742dcb4e9b65668cc1755d055e198440fad3841450de904b043f07f
[2025-06-18 04:47:06] INFO: Message decrypted successfully
Decrypted: This is a test message for cryptographic verification.
Test: PASSED
================================
santt@Santt-pc:~/Área de trabalho/cript$ ./v11 -t
=== Cryptographic Test Vector ===
Password: SecureTestPassword123!@#
Message: This is a test message for cryptographic verification.
[2025-06-18 04:47:16] INFO: Message encrypted successfully
Encrypted (hex): 039ca8db9811d9c9a4f753f6cdc348a5e1a8a16ae5575798b67f7666d2238b526800000000a0b9e6bfca9147423b00a8823443f1ed32fbb2a145d1a76129eef6edd8c35f16d838a85ff2545cf6734486c39d06f010127c2a05d5d5edbf2b82649a287d55888e1c4ceb9970
[2025-06-18 04:47:16] INFO: Message decrypted successfully
Decrypted: This is a test message for cryptographic verification.
Test: PASSED
================================
santt@Santt-pc:~/Área de trabalho/cript$ ./v11 -t
=== Cryptographic Test Vector ===
Password: SecureTestPassword123!@#
Message: This is a test message for cryptographic verification.
[2025-06-18 04:47:40] INFO: Message encrypted successfully
Encrypted (hex): 03024a4d329d64a97435476c3927d06672777d8008f357a7579faf3ff83c8b526800000000df8f0a23acf90558e39ee8dbfe3099a267bf3af9c0f4cfa0a29ed1b0722809d907a3b55f9bccbfcbfdd378166232c6bf23e623bdc904b09dfcb49857a5166532dc29a8d726fe
[2025-06-18 04:47:40] INFO: Message decrypted successfully
Decrypted: This is a test message for cryptographic verification.
Test: PASSED
================================
```

---

## 🚫 Disclaimer Final

**Este código é uma experiência criptográfica paranoica.**  
**Não use em produção. Não dependa disso para proteger dados críticos de vida ou morte.**  
**Use por sua conta e risco.**

---

**Versão:** V3 - Junho 2025  
**Autor:** Alguém que odeia cifras determinísticas.
