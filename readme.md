
# 🔐 HardenedEntropyCipher V3 (C Edition) - Projeto de Louco com Paranoia em Camadas 

## 📌 Sobre

A **HardenedEntropyCipher V3 (C Edition)** é uma cifra experimental, totalmente overengineered, criada com o objetivo único de ser difícil de quebrar, difícil de analisar e, provavelmente, difícil de entender.

> ⚠️ **AVISO DE SANIDADE:**  
Este projeto nasceu de uma mente paranoica e é fruto de insônia + café + ódio por padrões simples demais.  
**Não existe auditoria externa, nem compliance FIPS, nem NIST. Só caos.**

---

## 📜 Principais Características

- ✅ Criptografia AEAD moderna (ChaCha20-Poly1305 IETF via libsodium)
- ✅ Derivação de chave com Argon2id (OPSLIMIT_INTERACTIVE / MEMLIMIT_INTERACTIVE)
- ✅ Controle de versão de payload (`VERSION_BYTE`)
- ✅ Header autenticado (AEAD + Additional Data)
- ✅ Proteção contra replay via timestamp
- ✅ Validação de senha com análise de entropia + verificação de classes de caracteres
- ✅ Zeroização manual de buffers sensíveis
- ✅ Payload Hex-safe para transporte por canais inseguros
- ✅ Limitação de tamanho de payload para evitar DoS (64KB máximo)

---

## 📈 Comparação com Outras Cifras Conhecidas

| Recurso | AES-GCM | ChaCha20-Poly1305 | HardenedEntropyCipher V3 |
|---|---|---|---|
| Validação de senha embutida | ❌ | ❌ | ✅ |
| Header customizado com versionamento | ❌ | ❌ | ✅ |
| Timestamp Anti-Replay | ❌ | ❌ | ✅ |
| Buffer zeroization manual | Parcial | Parcial | ✅ |
| Output pronto pra transporte em Hex | ❌ | ❌ | ✅ |
| Dependência de libs | OpenSSL | Libsodium | Libsodium |
| Performance | Alta | Alta | Baixa 😂 |
| Produção Ready | ✅ | ✅ | ❌ Experimental |

---

## 📐 Estrutura do Payload

```
[1 byte Versão] +
[24 bytes Salt] +
[12 bytes Nonce] +
[8 bytes Timestamp] +
[Ciphertext + MAC (16 bytes)]
```

---

## 🛡️ Proteções Incluídas

| Proteção | Status |
|---|---|
| Senha fraca rejeitada | ✅ |
| Resistência mínima a timing attacks | ✅ (por libsodium) |
| Wipe de memória sensível | ✅ |
| Validação de timestamp | ✅ |
| AEAD + Associated Data | ✅ |
| Input sanitization com força bruta | ✅ |
| Check de versão de payload | ✅ |
| Hex encoding seguro | ✅ |

---

## ✅ Casos de Uso (… Ou não)

- ✅ Criptografar configs, tokens ou blobs pequenos que você PRECISA descriptografar depois.
- ✅ Usar como segunda camada de proteção sobre uma cifra já existente (Double Encryption Lovers ❤️).
- ❌ Não usar como substituto de bcrypt, Argon2id puro ou PBKDF2 para armazenamento de senhas.

---

## 🚀 Como Compilar

```bash
$ make
```

> Obs: Requer **libsodium >= 1.0.16**

---

## 🎯 Exemplos de Uso

### Criptografar:

```bash
./v3 -e -k "MinhaSenhaForte123!" -m "Mensagem secreta"
```

### Decriptar:

```bash
./v3 -d -k "MinhaSenhaForte123!" -h "<hex_da_mensagem>"
```

### Teste de Vetor Interno:

```bash
./v3 -t
```

---

## 🧪 Benchmark (No meu Ryzen 5 de pobre)

| Tamanho | Tempo |
|---|---|
| 10 bytes | ~150ms |
| 1KB | ~160ms |
| 10KB | ~180ms |

> **Obs:** Este código não nasceu pensando em performance. Nasceu pensando em deixar analistas forenses tristes.

---

## ⚠️ Aviso Final

> **Este projeto é um laboratório criptográfico paranoico feito por puro amadorismo. Não use em produção. Não me processe. Não reclame depois.**

Se você chegou até aqui e entendeu metade... parabéns, já está meio maluco também.

---

**Versão:** V3 - June 2025  
**Autor:** Um dev que dorme abraçado com o manual do libsodium.
