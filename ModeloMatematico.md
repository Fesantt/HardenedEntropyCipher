
# HardenedEntropyCipher V3 - Modelo Matemático

## 📚 Introdução

A HardenedEntropyCipher V3 é uma cifra simétrica de fluxo e bloco híbrida com foco em **entropia embarcada**, **forward secrecy por sessão** e **posicionamento pseudo-aleatório de ruído**. Este documento descreve o **modelo matemático puro**, sem foco em implementação de código.

---

## 🧮 Modelo Matemático

### 1. Derivação de Chaves (KDF)

Para cada sessão, as chaves são derivadas usando múltiplos passos de expansão e mistura:

**Inputs:**

- MasterKey: \( K \)
- Salt aleatório: \( S \)
- SessionID: \( SID \)
- Propósito: \( P \)
- Iterações: \( r \)

**Processo:**

1. \( V = 	ext{SHA-256}("v" + 	ext{version} + P + S) \)
2. \( K_1 = 	ext{PBKDF2-SHA256}(K, V, r) \)
3. \( K_2 = 	ext{PBKDF2-SHA512}(K, S, r/2) \)
4. \( K_{	ext{final}} = 	ext{BLAKE2b}(K_1 || K_2, 	ext{key} = V_{	ext{keyed}}) \)

De onde:

\[ K_{	ext{final}} = 	ext{Concatenação} \left( AES_{	ext{key}}, 	ext{ChaCha}_{	ext{key}}, 	ext{HMAC}_{	ext{key}} 
ight) \]

---

### 2. Entropy PRNG Positioning (LCG Melhorado)

O posicionamento dos bytes de entropia embarcada é calculado por um **PRNG determinístico por sessão**.

**Seed:**

\[ seed = 	ext{SHA-256}(K || S || SID || 	ext{"entropy\_seed"})_{0-8\ bytes} \]

**PRNG:**

\[ x_{n+1} = (a \cdot x_n + c) \mod m \]

Com:

- \( a = 1664525 \)
- \( c = 1013904223 \)
- \( m = 2^{32} \)

Para cada \( n \), gera-se uma posição de inserção de entropia dentro do ciphertext + noise space.

---

### 3. Dual Layer Encryption

**Entrada:** Dados \( D \), com padding e compressão opcional.

**Passo 1:**

\[ C_1 = 	ext{AES-CBC-Encrypt}(K_{	ext{AES}}, IV, D_{	ext{padded}}) \]

**Passo 2:**

\[ Nonce = 	ext{SHA-256}(IV || SID)_{0-12\ bytes} \]

\[ C_2 = 	ext{ChaCha20-Encrypt}(K_{	ext{ChaCha}}, Nonce, C_1) \]

**Resultado bruto antes do embedding de entropia:** \( C_2 \)

---

### 4. Embedding de Entropia

Dado o **entropy_ratio** \( r_e \), para cada byte de \( C_2 \), inserimos \( r_e \) bytes de entropia pseudo-aleatória.

**Final length:**

\[ L_{	ext{final}} = |C_2| + \left( |C_2| 	imes r_e 
ight) \]

Posições de entropia definidas por \( PRNG_{	ext{session}} \).

---

### 5. MAC Final

\[ MAC = 	ext{HMAC-SHA256}(K_{	ext{MAC}}, Header || Embedded\_Data) \]

Onde o Header inclui metadados como versão, rounds, entropy ratio, flags, seed length etc.

---

### 6. Descriptografia (Reverse Flow)

1. Verificação de versão e integridade via MAC.
2. Reconstrução de posições de entropia via PRNG.
3. Extração reversa do ciphertext puro.
4. Descriptografia reversa (ChaCha → AES → Unpadding → Decompress).

---

## 📌 Propriedades Matemáticas Alcançadas

| Propriedade                   | Status |
|-------------------------------|-------|
| Não Determinismo                | ✅ |
| Reversibilidade                 | ✅ |
| Sem State Externo Persistente   | ✅ |
| Forward Secrecy                 | ✅ |
| Difusão de Alta Entropia        | ✅ |
| Proteção Contra CPA/CCA Básica  | ✅ |

---

## 🏁 Conclusão

Este modelo matemático busca oferecer uma base sólida para futura formalização acadêmica e implementação multi-linguagem. Ajustes podem ser feitos conforme peer review e auditoria de segurança avançada.

---

**Autor:** Felipe(2025)  
**Licença:** MIT
