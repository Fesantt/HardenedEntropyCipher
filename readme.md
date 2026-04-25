# HardenedEntropyCipher V3 — C# Edition

Cifra **não-determinística**, **reversível**, com **entropia embutida** — reescrita completa do [original em C](../cipher.c) com suporte adicional a **criptografia de arquivos**.

> Mesmo plaintext + mesma senha → outputs **sempre diferentes**. Matematicamente garantido.



## Características

| Recurso | Status |
|---|---|
| Não-determinística por design (Salt + Nonce por operação) | ✅ |
| ChaCha20-Poly1305 IETF (AEAD) via .NET 8 | ✅ |
| Argon2id via **libsodium** (3 iter, 64 MB) | ✅ |
| Header completamente autenticado via AEAD Additional Data | ✅ |
| Proteção anti-replay via timestamp (janela 7 dias) | ✅ |
| Zeroing de chaves e buffers de plaintext | ✅ |
| Validação de senha com análise de entropia (mín. 60 bits) | ✅ |
| Criptografia de **texto** com output hex | ✅ |
| Criptografia de **arquivos** com AEAD chunked | ✅ |
| Proteção anti-reordenação de chunks | ✅ |
| Verificação de integridade de tamanho de arquivo | ✅ |

---

## Dependências

| Biblioteca | Função | Distribuição |
|---|---|---|
| `libsodium 1.0.20` | Argon2id KDF (`crypto_pwhash`) | Bundled via NuGet |
| `Sodium.Core 1.4.0` | Wrapper C# sobre libsodium | NuGet |
| `.NET 8 runtime` | ChaCha20-Poly1305, CSPRNG, zeroing | .NET SDK / Runtime |

A `libsodium.dll` vem **automaticamente** pelo pacote NuGet `libsodium` — não é necessário instalar nada separado.

---

## Instalação no Windows

### Opção 1 — Self-contained (recomendado, sem dependências externas)

Gera um único `.exe` com tudo embutido, incluindo a `libsodium.dll` e o runtime .NET:

```powershell
cd cs
dotnet publish -c Release -r win-x64 --self-contained -o publish\
```

O diretório `publish\` conterá:
```
publish\
  v3cs.exe          ← executável principal
  libsodium.dll     ← bundled automaticamente pelo NuGet
  (demais arquivos do runtime)
```

Coloque o conteúdo de `publish\` em qualquer diretório e execute `v3cs.exe` diretamente. **Nenhuma instalação adicional necessária.**

---

### Opção 2 — Runtime-dependent (menor tamanho, requer .NET 8 instalado)

```powershell
cd cs
dotnet publish -c Release -r win-x64 --no-self-contained -o publish\
```

Neste caso o diretório de saída contém `v3cs.exe` e `libsodium.dll`. O usuário precisa ter o **.NET 8 Runtime** instalado: [aka.ms/dotnet/8](https://aka.ms/dotnet/8)

---

### Onde fica a `libsodium.dll`

A `libsodium.dll` é copiada automaticamente para a pasta de saída pelo .NET durante o build/publish. Você **não** precisa copiar manualmente de nenhum lugar.

Se por algum motivo o .NET não encontrar a DLL em tempo de execução, coloque-a em um destes locais (em ordem de prioridade):

1. **Mesmo diretório do executável** (sempre funciona)
2. **Variável de ambiente `PATH`**
3. `C:\Windows\System32` (para uso global no sistema — não recomendado)

Para verificar que a DLL está sendo encontrada:

```powershell
v3cs -t
# Se exibir "Text test: PASSED" e "File test: PASSED", libsodium está funcionando.
```

---

### Build simples (desenvolvimento)

```powershell
cd cs
dotnet build -c Release
dotnet run -c Release -- -t       # self-test
```

---

## Uso

```powershell
# Criptografar texto → hex
v3cs -e  -k "MinhaS3nh@Forte2025!" -m "dados secretos"

# Decriptografar texto ← hex
v3cs -d  -k "MinhaS3nh@Forte2025!" -h 04f3bb85...

# Criptografar arquivo → .hec
v3cs -ef -k "MinhaS3nh@Forte2025!" -i segredo.pdf  -o segredo.pdf.hec

# Decriptografar arquivo ← .hec
v3cs -df -k "MinhaS3nh@Forte2025!" -i segredo.pdf.hec -o segredo.pdf

# Self-test / test vectors (inclui prova de não-determinismo)
v3cs -t
```

---

## Layout do Payload

### Texto (output hex)

```
[1  byte ] Versão (0x04)
[16 bytes] Salt   — crypto_pwhash_SALTBYTES, gerado aleatoriamente por operação
[12 bytes] Nonce  — ChaCha20-Poly1305 IETF, gerado aleatoriamente por operação
[8  bytes] Timestamp Unix (LE) — autenticado no AEAD
[N  bytes] Ciphertext — ChaCha20-Poly1305
[16 bytes] MAC (Poly1305 tag)
```

### Arquivo binário (.hec)

```
[4  bytes] Magic "HEC\x04"
[1  byte ] Versão (0x04)
[16 bytes] Salt   — aleatório por operação
[12 bytes] Nonce base — aleatório por operação
[8  bytes] Timestamp Unix (LE)
[8  bytes] Tamanho original do arquivo (LE)
[chunks...]
```

Cada chunk:

```
[4  bytes] Tamanho do plaintext do chunk (LE)
[N  bytes] Ciphertext do chunk (mesmo tamanho que plaintext)
[16 bytes] MAC do chunk (Poly1305 tag)
```

---

## Audit de Segurança — C# vs. C original

### Cifra simétrica

| | C original | C# Edition |
|---|---|---|
| Algoritmo | `crypto_aead_chacha20poly1305_ietf_encrypt` (libsodium) | `System.Security.Cryptography.ChaCha20Poly1305` (.NET 8) |
| Nonce | 12 bytes IETF | 12 bytes IETF — idêntico |
| Tag (MAC) | 16 bytes Poly1305 | 16 bytes Poly1305 — idêntico |
| Header autenticado (AAD) | `version+salt+nonce+timestamp` | Mesmo conteúdo — idêntico |

**Resultado: paridade completa.** Mesma primitiva criptográfica, mesmos parâmetros.

---

### Derivação de chave (KDF)

| | C original | C# Edition |
|---|---|---|
| Implementação | `crypto_pwhash` — libsodium | `PasswordHash.ArgonHashBinary` — **libsodium via Sodium.Core** |
| Algoritmo | `crypto_pwhash_ALG_ARGON2ID13` | `ArgonAlgorithm.Argon_2ID13` — mesmo enum interno da libsodium |
| Iterações | 2 (`OPSLIMIT_INTERACTIVE`) | **3** — Sodium.Core exige mínimo 3 para Argon2id¹ |
| Memória | 67 108 864 bytes (64 MB) | 67 108 864 bytes (64 MB) — idêntico |
| Salt | 16 bytes (`crypto_pwhash_SALTBYTES`) | 16 bytes — idêntico |
| Tamanho da chave | 32 bytes | 32 bytes — idêntico |

> ¹ O wrapper Sodium.Core 1.4.0 valida `opsLimit >= 3` para Argon2id no lado C#, embora libsodium aceite 2. Usamos 3 iterations: mesma memória hardness do original, custo computacional ligeiramente maior — efeito na segurança: positivo.

**Resultado: paridade com libsodium como backend real.** O Argon2id executado é o mesmo código C que o original usa, derivando chaves com o mesmo algoritmo e praticamente os mesmos parâmetros.

---

### Entropia e não-determinismo

| | C original | C# Edition |
|---|---|---|
| Salt aleatório por operação | `randombytes_buf` (libsodium CSPRNG) | `RandomNumberGenerator.GetBytes` (OS CSPRNG) |
| Nonce aleatório por operação | `randombytes_buf` | `RandomNumberGenerator.GetBytes` |
| Timestamp embutido | Sim | Sim |
| Output idêntico possível? | Não (2⁻²⁵⁶ por nonce + salt) | Não — mesmo espaço |

**Resultado: paridade completa.** Ambos usam o CSPRNG do sistema operacional.

---

### Proteção anti-replay

| | C original | C# Edition |
|---|---|---|
| Timestamp no header | Sim | Sim |
| Tolerância no futuro | 300 s | 300 s — idêntico |
| Tolerância no passado | 7 dias | 7 dias — idêntico |
| Timestamp autenticado pelo AEAD | Sim | Sim — faz parte do AAD |

**Resultado: paridade completa.**

---

### Zeroing de memória sensível

| Buffer | C original | C# Edition |
|---|---|---|
| Chave de criptografia | `sodium_memzero` no bloco de limpeza | `CryptographicOperations.ZeroMemory` no `finally` |
| Bytes da senha (KDF input) | Não zerado explicitamente | `ZeroMemory` no `finally` do `DeriveKey` |
| Plaintext de texto | Via `sodium_free` ao liberar o secure buffer | `ZeroMemory` após uso — mesmo path de erro |
| Plaintext de chunks de arquivo | Via `sodium_free` | `ZeroMemory` após escrita em disco — mesmo path de erro |
| Alocador | `sodium_malloc` (guard pages + `mlock`) | `byte[]` heap gerenciado — **ver limitação abaixo** |

**Resultado: paridade no zeroing explícito. Diferença arquitetural no alocador.**

O `sodium_malloc` aloca em páginas isoladas com guard pages e previne swap via `mlock`. Em .NET, o equivalente exigiria P/Invoke direto para `VirtualAlloc` + `VirtualLock`. Mitigação: zeroing imediato com `CryptographicOperations.ZeroMemory` em todos os paths de execução, incluindo branches de erro.

---

### Validação de senha

| | C original | C# Edition |
|---|---|---|
| Comprimento mínimo | 12 chars | 12 chars — idêntico |
| Comprimento máximo | 1024 chars | 1024 chars — idêntico |
| Rejeição de controle chars | `c < 32 \|\| c == 127` | Idêntico |
| Exigência de classes de caracteres | 3 classes se `len < 16` | 3 classes se `len < 16` — idêntico |
| Entropia mínima | 60 bits via `log2(charset) * len` | 60 bits — fórmula idêntica |

**Resultado: paridade completa.**

---

### Proteção anti-reordenação de chunks (exclusivo do modo arquivo)

Funcionalidade adicional sem equivalente no C original (que não suporta arquivos):

- **Nonce único por chunk**: `baseNonce XOR chunkIndex` — reutilização de nonce impossível mesmo com plaintext idêntico entre chunks.
- **AAD por chunk**: `magic + salt + baseNonce + timestamp + chunkIndex` — um chunk extraído de um arquivo não pode ser inserido em outro sem invalidar o MAC.
- **Verificação de tamanho total**: truncamento do arquivo é detectado após decifrar todos os chunks.

---

### Limitações conhecidas vs. C original

| Limitação | Impacto prático | Mitigação |
|---|---|---|
| Sem `sodium_malloc` (guard pages + `mlock`) | Chaves/plaintext no heap gerenciado; possível swap para disco | `ZeroMemory` imediato em todos os paths |
| Strings .NET são imutáveis | O plaintext retornado como `string` não pode ser zerado | O `byte[]` intermediário é zerado antes de criar a string |
| GC pode criar cópias internas | Buffer pode existir em mais de um endereço antes do zeroing | Mitigado pelo zeroing rápido; GC raramente copia arrays grandes |
| `opsLimit` = 3 vs 2 do original | Custo de CPU ligeiramente maior na derivação | Efeito positivo na segurança |

---

## Integração da libsodium

O backend de KDF usa a `libsodium.dll` real via `Sodium.Core`. A mesma `libsodium 1.0.20` que o projeto original em C compila contra está sendo chamada aqui, mas pelo lado .NET via P/Invoke gerenciado pelo Sodium.Core.

```
v3cs.exe
  └── Sodium.Core 1.4.0
        └── libsodium 1.0.20.1 (libsodium.dll / libsodium.so)
              └── crypto_pwhash()   ← Argon2id real, em C
```

O `ChaCha20Poly1305` permanece no lado .NET (implementação nativa do .NET 8) — equivalente em segurança, sem dependência extra de DLL para a cifra.

---

## Teste de Não-Determinismo

```
Password : SecureTestPassword123!@#
Message  : This is a test message for cryptographic verification.

Cipher 1 : 04f3bb85326ef2ac90bfe05ca08d42f1...
Cipher 2 : 042a74d36f63cfefaa274830c998af94...

Different: YES (non-deterministic)
Text test: PASSED
File test: PASSED
```

Mesmo plaintext + mesma senha → ciphertexts completamente diferentes em cada execução.

---

## Comparativo geral

| Recurso | AES-GCM | ChaCha20-Poly1305 | C original | **C# Edition** |
|---|---|---|---|---|
| Não-determinística | ❌ | ✅ | ✅ | ✅ |
| Header autenticado com timestamp | ❌ | ❌ | ✅ | ✅ |
| Argon2id via libsodium | ❌ | ❌ | ✅ | ✅ |
| Zeroing de buffers sensíveis | Opcional | Parcial | ✅ | ✅ |
| Anti-replay | ❌ | ❌ | ✅ | ✅ |
| libsodium como backend real | ❌ | ❌ | ✅ | ✅ (KDF) |
| Suporte a arquivos grandes | ❌ | ❌ | ❌ | ✅ |
| Anti-reordenação de chunks | — | — | — | ✅ |
| Output hex para transporte ASCII | ❌ | ❌ | ✅ | ✅ |

---

**Versão:** V3 — C# Edition  
**Base:** [HardenedEntropyCipher V3 C Edition](../cipher.c)  
**Dependência nativa:** libsodium 1.0.20 (bundled via NuGet)  
**Autor:** Alguém que ainda odeia cifras determinísticas, mas agora em C#.
