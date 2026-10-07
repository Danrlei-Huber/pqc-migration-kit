# Manifesto de evidência — validação do módulo

Gerado por `mvn test -Pvalidacao` em 2026-10-07T15:24:09.066752487-03:00.

Todo artefato listado abaixo é **material público** — certificados, requisições, chaves públicas e assinaturas. Nenhuma chave privada é gravada.

Ambiente completo em [`ambiente.txt`](ambiente.txt). Versão legível por máquina em [`manifesto.json`](manifesto.json).

## Resumo

- Casos executados: **50**
- Casos pulados: **0**
- Artefatos gravados: **200**
- Bytes totais: **463427**

## 05-assinatura-dados

### envelope-hibrido — Envelope de assinatura híbrida

- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Dados assinados:** 71 bytes
- **Envelope completo:** 3415 bytes
- **Prefixo de tamanho:** 4 bytes (big-endian)
- **Assinatura clássica:** 102 bytes
- **Assinatura ML-DSA-65:** 3309 bytes
- **Sobrecarga sobre a clássica isolada:** 33.5x

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `05-assinatura-dados/envelope-hibrido/dados-assinados.bin` | 71 | `438ac4ffc84f9b34b0a5ee67d4ca1c6bb8865b07f2fb4fbce363b5570037d5e9` |
| `05-assinatura-dados/envelope-hibrido/envelope.bin` | 3415 | `300057dde40702a776f4c16b302a17457113ea7568386553e4459b6c27435903` |
| `05-assinatura-dados/envelope-hibrido/assinatura-classica.bin` | 102 | `786ea962a6092084bf433ba590c8346bc29e9c1da02841cfa360d340514c0e12` |
| `05-assinatura-dados/envelope-hibrido/assinatura-pqc.bin` | 3309 | `8c74747396ff206660c94d336a9a98dfc994f697339c14c7699bf23e5cbc7fbb` |
| `05-assinatura-dados/envelope-hibrido/envelope.hex` | 10245 | `d90a0b28249279774c99f98331b334d3721cf384bb5f1f53781c6434c34b78d8` |
| `05-assinatura-dados/envelope-hibrido/relatorio-assinatura.txt` | 443 | `1d307b7828039fbf092575b978f26db6136bacf2fe681faa8f563bfb2d83f9d0` |
| `05-assinatura-dados/envelope-hibrido/comparacao.txt` | 649 | `fd0a4a8595976b98bf0e89cbe585889bb70d9139401927964b8471c637fab9d6` |
| `05-assinatura-dados/envelope-hibrido/estatisticas.txt` | 279 | `ee0836912244f6b9de50b1fbbed4fcb952de33c4a9ec30a21abe09be41977d3d` |
| `05-assinatura-dados/envelope-hibrido/relatorio.txt` | 639 | `2649e483c45f8ef9895d9f4101e02eda4a34ba3f531197f201f6c2b12c3a42dd` |

### verificacao-apenas-classica — Conferência isolada da metade clássica

- **Verificação híbrida (E):** VÁLIDA
- **Verificação apenas clássica:** VÁLIDA
- **Algoritmo clássico:** ECDSA
- **Algoritmo pós-quântico:** ML-DSA-65

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `05-assinatura-dados/verificacao-apenas-classica/assinatura-classica.bin` | 104 | `5e99b4fe9e0aec56b8da1981b92f48836dcc7d839efbd03c8571ba71327f38ca` |
| `05-assinatura-dados/verificacao-apenas-classica/assinatura-pqc.bin` | 3309 | `e7e0b7916615b6b11329fb22b7e04ee340ddc553bb81622515f664ce1e7de770` |
| `05-assinatura-dados/verificacao-apenas-classica/relatorio.txt` | 539 | `6c43b11b513b8738453c686950b21ee02fb4fdd5dab043fc9733442101b479f0` |

### separacao-por-contexto — Separação de domínio pelo contexto FIPS 204

- **Contexto usado na assinatura:** "faturamento"
- **Verifica com "faturamento":** VÁLIDA
- **Verifica com "auditoria":** INVÁLIDA
- **Verifica sem contexto:** INVÁLIDA
- **Assinatura sem contexto, verificada com um:** INVÁLIDA
- **Limite do contexto:** 255 bytes, imposto pelo provedor

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `05-assinatura-dados/separacao-por-contexto/envelope-ctx-faturamento.bin` | 3415 | `db98819496a2bd0df13d444e3556a81d58f0efce228be3d4f9b3be175d6743d8` |
| `05-assinatura-dados/separacao-por-contexto/envelope-sem-contexto.bin` | 3416 | `ece4e7f586b046b8f3a66032637823392c31589c11479d6b43981cadd769a2e8` |
| `05-assinatura-dados/separacao-por-contexto/contexto-faturamento.bin` | 11 | `69e151e6bb68588d18413cd16d354f2844f433b343bd4f431e17713e28b33047` |
| `05-assinatura-dados/separacao-por-contexto/relatorio.txt` | 728 | `94997f18d8aee6e8386f4f31e0167825cf0787473b6f2fb695e63c5475744abd` |

### logica-e-adulteracao — Verificação sob lógica E e detecção de adulteração

- **Assinatura íntegra:** VÁLIDA
- **Dado com 1 bit alterado:** INVÁLIDA
- **Metade clássica corrompida:** INVÁLIDA
- **Metade pós-quântica corrompida:** INVÁLIDA

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `05-assinatura-dados/logica-e-adulteracao/envelope-integro.bin` | 3416 | `b96bc172acb9f73af5abf59628d3fe6715ab15ed97cf8f522940a7b137ad2b06` |
| `05-assinatura-dados/logica-e-adulteracao/envelope-classica-corrompida.bin` | 3416 | `0915d9e83499c8bdc5268a88d6eed59300efcca9eb66c7da40cb1468d610592c` |
| `05-assinatura-dados/logica-e-adulteracao/envelope-pqc-corrompida.bin` | 3416 | `37c847acce7b44399c0777b3f2e604c7e61bfc2491db2b486078426edb9b8fe4` |
| `05-assinatura-dados/logica-e-adulteracao/dado-adulterado.bin` | 71 | `12d8c367735ed053a33a8a5b6fb5a33c20199e7ff6eb9abe764e538f58bc44d3` |
| `05-assinatura-dados/logica-e-adulteracao/relatorio.txt` | 650 | `159301ebe0cc5e3fb2130e33e4d3c8c64d4534e96e387c242da263a30192097e` |

## 02-emissao-certificados

### criticidade-compativel — Extensões alternativas não críticas

- **altSignatureExtensionsCritical:** false
- **Extensões críticas:** [2.5.29.19, 2.5.29.15]
- **Extensões não críticas:** [2.5.29.72, 2.5.29.73, 2.5.29.74, 2.5.29.35, 2.5.29.14, 2.5.29.37]
- **Consequência:** verificador clássico ignora as extensões e aceita pela assinatura clássica

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/criticidade-compativel/certificado.der` | 5903 | `0052e90aac725a78882efeb8ae35610a03304d928e3587d1c89a237869ae180a` |
| `02-emissao-certificados/criticidade-compativel/certificado.pem` | 8049 | `9fb414bcbac6c0301ba0181d4fcda270bd079fe59eed4d22345ad1a173490c84` |
| `02-emissao-certificados/criticidade-compativel/relatorio.txt` | 484 | `f532de771d99cf7d91dfe071ad7d2c3eaf84bab53b3c84f5834547401c08fed4` |

### criticidade-estrita — Extensões alternativas críticas

- **altSignatureExtensionsCritical:** true
- **Extensões críticas:** [2.5.29.19, 2.5.29.73, 2.5.29.74, 2.5.29.15]
- **Extensões não críticas:** [2.5.29.72, 2.5.29.35, 2.5.29.14, 2.5.29.37]
- **Consequência:** verificador conforme a RFC 5280 rejeita: impede downgrade silencioso

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/criticidade-estrita/certificado.der` | 5907 | `17970d472198bee0a342881dc9526fc7219f0ce055424771c469d9b20b0ef5f9` |
| `02-emissao-certificados/criticidade-estrita/certificado.pem` | 8054 | `686899f7f6598bcbf32a89e8b4cbabbd941f327e74fa7b3e62900f20d93cd774` |
| `02-emissao-certificados/criticidade-estrita/relatorio.txt` | 465 | `5e9ce3e88be0b93cc07064ea8e6d759a786bb297d60e6973cec02493d0cb17f7` |

### nivel-128 — Certificado híbrido autoassinado de 128 bits

- **Par de algoritmos:** ECDSA-256 + ML-DSA-44
- **Algoritmo de assinatura:** SHA256WITHECDSA (OID 1.2.840.10045.4.3.2)
- **Sujeito:** C=BR,O=TCC,CN=nivel128.tcc.br
- **Número serial:** 1104752184784466849198160105332526277007182907437
- **Certificado completo:** 4279 bytes (DER)
- **2.5.29.72 subjectAltPublicKeyInfo:** 1338 bytes, não crítica
- **2.5.29.73 altSignatureAlgorithm:** 15 bytes, não crítica
- **2.5.29.74 altSignatureValue:** 2429 bytes, não crítica

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/nivel-128/certificado.der` | 4279 | `7828d3475acba5ad27c9eb9c3c55f6f3f60fe16fafbfc3c062dbe94b1efe0ba0` |
| `02-emissao-certificados/nivel-128/certificado.pem` | 5852 | `389515935e05c06d865f4b74f1764b1c864995110d6d3e8169152a47a348c4db` |
| `02-emissao-certificados/nivel-128/inspecao.txt` | 1188 | `7982aafa93eaf4a5730afdc0a355fca954ab07313973b0700481de51141b2bec` |
| `02-emissao-certificados/nivel-128/extensao-2.5.29.72.der` | 1338 | `2131ccbd9bb92b90c5afb92c7dd4f3fc5dd0eacc7b1774b2aa29c61915f55f23` |
| `02-emissao-certificados/nivel-128/extensao-2.5.29.73.der` | 15 | `20969a16b72e821aeab485aedc65b69ba6c8727a892ef27e49ec8638250d53b3` |
| `02-emissao-certificados/nivel-128/extensao-2.5.29.74.der` | 2429 | `213dedf8f1d13b1407df1db54c9945eca3965b72aebf09dc0e2328e96ac62beb` |
| `02-emissao-certificados/nivel-128/openssl-x509.txt` | 5573 | `65d33f756f670d8bb791f5cac4fabe0f90e7d56949204d4e0a72033f6bbe3b4d` |
| `02-emissao-certificados/nivel-128/relatorio.txt` | 833 | `7ab3830f132287a6b39423316c8f3ed7883c78491bb8b29c2a1c4726f2f54c1e` |

### nivel-192 — Certificado híbrido autoassinado de 192 bits

- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Algoritmo de assinatura:** SHA384WITHECDSA (OID 1.2.840.10045.4.3.3)
- **Sujeito:** C=BR,O=TCC,CN=nivel192.tcc.br
- **Número serial:** 1225463893390043835744584350536194311894601606787
- **Certificado completo:** 5868 bytes (DER)
- **2.5.29.72 subjectAltPublicKeyInfo:** 1978 bytes, não crítica
- **2.5.29.73 altSignatureAlgorithm:** 15 bytes, não crítica
- **2.5.29.74 altSignatureValue:** 3318 bytes, não crítica

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/nivel-192/certificado.der` | 5868 | `8de1f1094ea31da39aabef21f2637622b8e6206149d1d7f2a24714739e7fed0d` |
| `02-emissao-certificados/nivel-192/certificado.pem` | 8001 | `bd366f44cdb49ef45b667db17dfa9ef54cafdea09f7f7cdc80a6df14e62ed36d` |
| `02-emissao-certificados/nivel-192/inspecao.txt` | 1189 | `387dccfbcd3b9b8142c48188a831260354b8ce16e5ca40921c5e3539808a8924` |
| `02-emissao-certificados/nivel-192/extensao-2.5.29.72.der` | 1978 | `a81da89cc6aa5f08f891f91784027eea87b042df7d3f88984648405c7b835955` |
| `02-emissao-certificados/nivel-192/extensao-2.5.29.73.der` | 15 | `6d1e60231e16fdca46f0b1adf7631e110b33a1a2a59722bd745ce87f7fa6cf86` |
| `02-emissao-certificados/nivel-192/extensao-2.5.29.74.der` | 3318 | `9ca8cffc31af396ada458b838c4a22271d729d0c2b3410c8ad861c79c8078f44` |
| `02-emissao-certificados/nivel-192/openssl-x509.txt` | 7350 | `abd4aff5118810f678c605f9203e549dd4a1f8cabd8bdfef99edaed06f44441d` |
| `02-emissao-certificados/nivel-192/relatorio.txt` | 833 | `470b0dfd05d808b6f96fb6870f162ba635e682c8976c6d606ad6cefcd8744325` |

### nivel-256 — Certificado híbrido autoassinado de 256 bits

- **Par de algoritmos:** ECDSA-521 + ML-DSA-87
- **Algoritmo de assinatura:** SHA512WITHECDSA (OID 1.2.840.10045.4.3.4)
- **Sujeito:** C=BR,O=TCC,CN=nivel256.tcc.br
- **Número serial:** 906116908993741077379487160361786197709165040686
- **Certificado completo:** 7902 bytes (DER)
- **2.5.29.72 subjectAltPublicKeyInfo:** 2618 bytes, não crítica
- **2.5.29.73 altSignatureAlgorithm:** 15 bytes, não crítica
- **2.5.29.74 altSignatureValue:** 4636 bytes, não crítica

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/nivel-256/certificado.der` | 7902 | `d4b6bb9729f0923de1f787f5400f43327d9765c9006974f2f6ffcafab9fcab04` |
| `02-emissao-certificados/nivel-256/certificado.pem` | 10755 | `8c368d7b4c9c9205fdc91eaf3c1f1b510617b828c6141ca053f07e2da611a12b` |
| `02-emissao-certificados/nivel-256/inspecao.txt` | 1188 | `4fc2c040a8c1c1e158fc5f396acb2fd28cb35e92345477aaf28240aeed68cf2c` |
| `02-emissao-certificados/nivel-256/extensao-2.5.29.72.der` | 2618 | `8b332029f5fa2235cec153a31dbe24ba2100c87a1bd61ea128a2e116366be9c0` |
| `02-emissao-certificados/nivel-256/extensao-2.5.29.73.der` | 15 | `17157d037c92aa80c313d9e7f97572f675f98a9651ecb9d3ad77e3485b3d6b3d` |
| `02-emissao-certificados/nivel-256/extensao-2.5.29.74.der` | 4636 | `1594bdda457712cf4ce6290c3c08fac8e9885891b592c2384ea4fbd947fcbe00` |
| `02-emissao-certificados/nivel-256/openssl-x509.txt` | 9587 | `623931d79a4663fa69467db925573e5ac0f7bf9280e506c132bd08d78b22bd30` |
| `02-emissao-certificados/nivel-256/relatorio.txt` | 832 | `c521e0dfc4ce1b70f85c76eb199722adead3d54e5ed6c9bfafecc40e6fab3e2e` |

### ordem-de-assinatura — Ordem de assinatura do modelo Catalyst

- **Assinatura alternativa sobre pre-TBS:** válida
- **Assinatura clássica sobre TBS:** válida

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/ordem-de-assinatura/tbs-certificate.der` | 5741 | `45d101d4810aa5ce2e1fd65d898a072745ce95f06c9975fe6a4e397b1c1cf842` |
| `02-emissao-certificados/ordem-de-assinatura/relatorio.txt` | 625 | `d15bfa59105d1ab4b6b4aabf90008f143cd2075f1c09c1499f96cc301dcb2406` |

### layer1-signer-externo — Emissão via Layer 1 com ContentSigner fornecido externamente

- **Assinador clássico:** 1.2.840.10045.4.3.3
- **Assinador alternativo:** 2.16.840.1.101.3.4.3.18
- **Chave privada exigida pelo construtor:** nenhuma
- **Validação contra si mesmo:** aprovada nas duas dimensões

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/layer1-signer-externo/certificado.der` | 5893 | `50b6e5b9163c7d536714ca477df998452a6f502e51d00aba4b2727d655c47ef5` |
| `02-emissao-certificados/layer1-signer-externo/certificado.pem` | 8037 | `eda19080340f82340ae92697e7235188ed9f23011abaf0787df1cae3ffee2cb8` |
| `02-emissao-certificados/layer1-signer-externo/relatorio.txt` | 436 | `7053ab44d4322ffa2a9554d8a57b57d32ce027af9df767892d617d20ee799c92` |

## 04-requisicoes-csr

### csr-nivel-128 — CSR híbrida de 128 bits

- **Par de algoritmos:** ECDSA-256 + ML-DSA-44
- **Algoritmo da assinatura:** SHA256withECDSA
- **Tamanho:** 4054 bytes (DER)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/csr-nivel-128/requisicao.der` | 4054 | `58ede5c0e55ca355e5488c7b9154846ac9fa91706edf284cb639ae4b4a1de606` |
| `04-requisicoes-csr/csr-nivel-128/requisicao.pem` | 5563 | `ba8012bf7c8bfb8a56d05ac2c58be23964516616ec12bd9f6213ec7a8bbe3298` |
| `04-requisicoes-csr/csr-nivel-128/relatorio.txt` | 292 | `fd77cc615e3d95211104b443b468375be014e3b74f93d611898f3eaa98e617f1` |

### csr-nivel-192 — CSR híbrida de 192 bits

- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Algoritmo da assinatura:** SHA384withECDSA
- **Tamanho:** 5645 bytes (DER)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/csr-nivel-192/requisicao.der` | 5645 | `b15bf2d3c1e299faf14cb9ad5e23fd7739fb0ebef789f2d8e1a1bdfd95da769d` |
| `04-requisicoes-csr/csr-nivel-192/requisicao.pem` | 7716 | `9fcecc392c65f0712473ae9ed53d4c0864f618b56e36bb8204e07002d3e9b7b6` |
| `04-requisicoes-csr/csr-nivel-192/relatorio.txt` | 292 | `324ec23436fc04b25770db2b1dd59c2a55b3baa18c25b6b7a425168d99bdfd61` |

### csr-nivel-256 — CSR híbrida de 256 bits

- **Par de algoritmos:** ECDSA-521 + ML-DSA-87
- **Algoritmo da assinatura:** SHA512withECDSA
- **Tamanho:** 7677 bytes (DER)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/csr-nivel-256/requisicao.der` | 7677 | `1babfe4a1fdeeeeba706c1625d215e95ca9e83296e927811277e289c07446e83` |
| `04-requisicoes-csr/csr-nivel-256/requisicao.pem` | 10466 | `587d7821a3032be84ec851622e42cef239b0d2ba878528191c364e8dca2365ed` |
| `04-requisicoes-csr/csr-nivel-256/relatorio.txt` | 292 | `c90660fc95044e40faf505dc169c34d8f6f780a615dba3d62b39b47ca08e0a87` |

### resumo-csr — Tamanho das requisições por nível

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/resumo-csr/tabela.txt` | 268 | `5020aeff4c0d2db124a8e503ada9a590d9d76e75924948b2db220d66e1c47ed3` |
| `04-requisicoes-csr/resumo-csr/relatorio.txt` | 119 | `3094617514575decb1556c4c72a86f3e2c51dcde2818f8026dde8ec4c9be0f17` |

### csr-hibrida-192 — Requisição PKCS#10 híbrida de 192 bits

- **Sujeito:** CN=requisitante.tcc.br,O=TCC,C=BR
- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Algoritmo da assinatura principal:** SHA384withECDSA (OID 1.2.840.10045.4.3.3)
- **Chave clássica (campo convencional):** 120 bytes
- **Atributo altSubjectPublicKeyInfo:** presente (2.5.29.72)
- **Requisição completa:** 5648 bytes (DER)
- **openssl req -text:** decodifica sem erro
- **openssl req -verify:** assinatura própria da CSR conferida

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/csr-hibrida-192/requisicao.der` | 5648 | `b4e2f2b288808e6a73320986ef487b5921adbd91f8d153d6ca290227ac406f6b` |
| `04-requisicoes-csr/csr-hibrida-192/requisicao.pem` | 7720 | `cf12fb36c2078aa7bae7cecafb7a74cb7a9b24793001adec5b9c03338b2392fb` |
| `04-requisicoes-csr/csr-hibrida-192/chave-publica-classica.der` | 120 | `67fed47c0deaa20341e0f17a3fd16fad15fad932977b9787cb337602a84d7833` |
| `04-requisicoes-csr/csr-hibrida-192/chave-publica-pqc.der` | 1974 | `df3a5579aa7f2ec754b9aedb3ad19c3be612659721f3c8db21d6a968b5ede573` |
| `04-requisicoes-csr/csr-hibrida-192/openssl-req.txt` | 1435 | `d31291479d14999538e1915212617b432ead3185eeb410d158290e1b097b58bf` |
| `04-requisicoes-csr/csr-hibrida-192/openssl-req-verify.txt` | 100 | `54ef14f6a4032ede536f4f8d3ba1ed32c058add5d92f39849b7e21ef889bdd52` |
| `04-requisicoes-csr/csr-hibrida-192/relatorio.txt` | 774 | `2c47aaa3910b91f100b7655385c833ff395082018aaf949ed66745a35da2ad0b` |

## 07-exportacao-inspecao

### sem-exportacao-de-chave-privada — Ausência deliberada de exportação de chave privada

- **Formatos suportados:** PEM e DER, apenas para certificados
- **Métodos que tratam chave privada:** nenhum

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `07-exportacao-inspecao/sem-exportacao-de-chave-privada/api-do-exportador.txt` | 178 | `7ac390c1eb53bfe725471a72be8ff818e53750cb6c242a7239f0a59ae4df7e48` |
| `07-exportacao-inspecao/sem-exportacao-de-chave-privada/relatorio.txt` | 479 | `1a85c2045f9946946968e57917ef486e1385ace2a4c4964c3c966fb07f9cf2af` |

### pem-equivale-der — Equivalência entre as saídas PEM e DER

- **Certificado em DER:** 5873 bytes
- **Certificado em PEM:** 8009 bytes (base64 com envelope)
- **PEM decodificado == DER:** sim, byte a byte
- **DER reconstrói o certificado:** sim
- **SHA-256 do DER:** bc57a57518902b51b042f1ad5f40de2b0058fc4671998047c5217ebe39e42e53

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `07-exportacao-inspecao/pem-equivale-der/certificado.der` | 5873 | `bc57a57518902b51b042f1ad5f40de2b0058fc4671998047c5217ebe39e42e53` |
| `07-exportacao-inspecao/pem-equivale-der/certificado.pem` | 8009 | `be4feaec38b2e02948a45077d913b38011fa63c87ed8d0c7bad6e48ea770dbf1` |
| `07-exportacao-inspecao/pem-equivale-der/relatorio.txt` | 479 | `74a7bbc42386ce6b1a85aff810f49d56e31155e1b6318338df2e2529fd54f6f1` |

### relatorios-de-inspecao — Relatórios produzidos pelos inspetores

- **Reconhecido como híbrido:** true
- **Chave pública:** ECDSA Public Key [ECDSA-384]
- **Tamanho total das assinaturas:** 3.33 KB

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `07-exportacao-inspecao/relatorios-de-inspecao/inspecao-hibrida.txt` | 1189 | `ab0a90c67cfa397b95b810f7f854debb7b8fc446c02b128300543e873013de8b` |
| `07-exportacao-inspecao/relatorios-de-inspecao/certificado.txt` | 469 | `15d832f2088ac77ea91173b45022ad3caee1a76b92af89c44acfa1bdd8f6009f` |
| `07-exportacao-inspecao/relatorios-de-inspecao/certificado-compacto.txt` | 106 | `4c85629ae5d4212ca670d874f2997b5ff8ddcbe8f631a12e63a2d5c6c603df70` |
| `07-exportacao-inspecao/relatorios-de-inspecao/chave-publica-classica.txt` | 272 | `46cfce1910cfbed26c0c5f2d6970163f29c0b59c32457130604be971d8d6913f` |
| `07-exportacao-inspecao/relatorios-de-inspecao/chave-publica-pqc.txt` | 224 | `9c1e840ae8c04e58beffa72918900d0753bd6c5325b81936ea8fceffe6970c89` |
| `07-exportacao-inspecao/relatorios-de-inspecao/assinaturas.txt` | 443 | `167b492f0bf7dc535ae1eaac286fe864e345ad50d85042deeaa0842958efce09` |
| `07-exportacao-inspecao/relatorios-de-inspecao/assinaturas-comparacao.txt` | 649 | `ed9e5164b3a72544f398c32082dc8bdb8ae860888457614f97ef663937c6cc1d` |
| `07-exportacao-inspecao/relatorios-de-inspecao/relatorio.txt` | 455 | `3a9e9368d4a798ef4276195cacddccc242fb0902d617b3167eb601e05d59c68a` |

### guarda-material-privado — Salvaguarda contra gravação de material privado

- **Extensões recusadas:** .key, .p12, .pkcs8, .jks
- **Nomes recusados:** qualquer um contendo "private" ou "privada"

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `07-exportacao-inspecao/guarda-material-privado/relatorio.txt` | 529 | `f23f1794380d3511d085a0eeec85bd844adabce883db980c9516e5e52d78f5c4` |

## 06-validacao

### cadeia-duas-dimensoes — Validação de cadeia nas dimensões clássica e pós-quântica

- **Elos da cadeia:** 2 (folha → raiz)
- **Dimensão clássica (CertPathValidator PKIX):** true
- **Dimensão pós-quântica (alt-signature por elo):** true
- **Veredito global:** true

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `06-validacao/cadeia-duas-dimensoes/folha.der` | 5980 | `e88e1610d6aafeca49712e50d756732c42fb276cfe6693468f174a35ecbfeda8` |
| `06-validacao/cadeia-duas-dimensoes/raiz.der` | 5871 | `8f8e0d583ca7a8795e80e82fadb0290178d6f9dcbccb928aa1b8dc79fb58e77e` |
| `06-validacao/cadeia-duas-dimensoes/relatorio.txt` | 675 | `7aa87f7a91065d0771468e181d0565289b26ad19ac8f299125abde0a8d7ce1ef` |

### modos-de-falha — Modos de falha detectados pela validação

- **Emissor errado — DNs:** false
- **Emissor errado — assinatura clássica:** false
- **Emissor errado — assinatura alternativa:** false
- **Chave pública de emissor errada:** false
- **Sem chave de emissor (folha emitida por CA):** false
- **Certificado sem extensões Catalyst — extensões:** false
- **Certificado sem extensões Catalyst — assinatura alternativa:** false

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `06-validacao/modos-de-falha/emissor-errado.txt` | 470 | `8965b8e9a11c7cde239501e5d29f8d39d7f13467c9cc4a71cf4365b0bba4ec13` |
| `06-validacao/modos-de-falha/chave-emissor-errada.txt` | 148 | `7f371c0e749b8efc702092a2147f63a004657819ce0d875cb48f4a19542ad7b9` |
| `06-validacao/modos-de-falha/sem-chave-de-emissor.txt` | 148 | `7f371c0e749b8efc702092a2147f63a004657819ce0d875cb48f4a19542ad7b9` |
| `06-validacao/modos-de-falha/sem-extensoes-catalyst.txt` | 263 | `d96de9fae82e422e4fd2e64032c5368c39c7da04687588889b0cfc2a17fe0dc1` |
| `06-validacao/modos-de-falha/certificado-sem-extensoes.der` | 551 | `b5e26b1d8b181869edc732cbf1facad83b09b526a42583de3ab750961c10847e` |
| `06-validacao/modos-de-falha/relatorio.txt` | 632 | `03035313b27e89e617ff452b56deff2a7da59f0b1b63a676e40fcc8207994ccf` |

### caminho-feliz — Certificado legítimo validado contra o emissor

- **Não expirado:** true
- **DNs e encadeamento:** true
- **Período de validade:** true
- **Chave pública:** true
- **Assinatura clássica:** true
- **Extensões PQC:** true
- **Assinatura alternativa:** true
- **Veredito global:** true

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `06-validacao/caminho-feliz/validation-result.txt` | 144 | `ce2ae0d5f451b5a701bf88f03556e388afb91ea83bcbe55ec1f63205b5bb0a05` |
| `06-validacao/caminho-feliz/folha.der` | 5978 | `7b63fd05c65a21fdf81e74bb0ced1d02db1c9289d8b5a031080aca70ebcabc5e` |
| `06-validacao/caminho-feliz/emissor.der` | 5873 | `aeab8cf45c1995969ac634b8f8de7dc790dd377570e3e80315b33c1db3d016b2` |
| `06-validacao/caminho-feliz/relatorio.txt` | 541 | `c3e655ec232b665b5fa5495ff2344b7f42e227c89adcbfd6d1bbc34423f332ce` |

## 01-geracao-chaves

### ml-dsa-44 — Chave pública ML-DSA-44

- **Nível de segurança:** 128 bits
- **OID:** 2.16.840.1.101.3.4.3.17
- **Chave crua (FIPS 204):** 1312 bytes
- **SPKI codificado:** 1334 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ml-dsa-44/chave-publica.der` | 1334 | `3e2b4539410e5c33362c5f24f673f6e9706f79c3c95fba0b412105fa40e7ed35` |
| `01-geracao-chaves/ml-dsa-44/chave-publica.hex` | 4002 | `18a2d9a02bb3025b90c18d63e11fdafaf8c979f7533d19ab85ee4b016e7a2c2a` |
| `01-geracao-chaves/ml-dsa-44/relatorio.txt` | 339 | `f6aa72c84e0499b8a2165192bef7f5e24af310926750ceab70d0d76847a21812` |

### ml-dsa-65 — Chave pública ML-DSA-65

- **Nível de segurança:** 192 bits
- **OID:** 2.16.840.1.101.3.4.3.18
- **Chave crua (FIPS 204):** 1952 bytes
- **SPKI codificado:** 1974 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ml-dsa-65/chave-publica.der` | 1974 | `2782bf8e7efff08d529a477cf65fe0bd79b3b4c209b20e4194614a359d6e8f41` |
| `01-geracao-chaves/ml-dsa-65/chave-publica.hex` | 5922 | `07a9cb3c34d5de7da3c3663cbadc82e2dd4a97004446f158e453c5e65d23be16` |
| `01-geracao-chaves/ml-dsa-65/relatorio.txt` | 339 | `f9cf080e228b1e1a611bfc487a9dbafbdd7a2a7a01dbea896efb4fd1cc3a8419` |

### ml-dsa-87 — Chave pública ML-DSA-87

- **Nível de segurança:** 256 bits
- **OID:** 2.16.840.1.101.3.4.3.19
- **Chave crua (FIPS 204):** 2592 bytes
- **SPKI codificado:** 2614 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ml-dsa-87/chave-publica.der` | 2614 | `afbf21fdf775f03c91a85627e53e173190c02a6404f9222d3dafa244cdc86d36` |
| `01-geracao-chaves/ml-dsa-87/chave-publica.hex` | 7842 | `36e42a84c0007e805eafe7d342a4bebf5b6345ed214a976e09dcab35a796daad` |
| `01-geracao-chaves/ml-dsa-87/relatorio.txt` | 339 | `68b6a902d8563d4f83cd2dfd537ced924dcfa624f83852c1feddc6d91d2717d9` |

### resumo-ml-dsa — Tabela comparativa das variantes ML-DSA

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/resumo-ml-dsa/tabela.txt` | 225 | `0d33a2301804efdd3a4ef9b35341aff90cd88f47dfa961f40acfe0350ff4d479` |
| `01-geracao-chaves/resumo-ml-dsa/relatorio.txt` | 128 | `c270eb4e565df49ac2a1aac762569b679b2e244f6c05276a71c7a3435e287515` |

### balanco-pares-prontos — Balanço de segurança dos pares prontos

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/balanco-pares-prontos/tabela.txt` | 492 | `3febb5f860285d507460355b1b11c61f2bdccbcf56f6e3155c62e4feb9c4dcd0` |
| `01-geracao-chaves/balanco-pares-prontos/relatorio.txt` | 198 | `3c101b4d9e5bec05d923436b3af74efccb0e06ff619233a68ba39a94291d22fe` |

### par-recomendado-128 — Par híbrido recomendado para 128 bits

- **Descrição:** ECDSA-256 + ML-DSA-44
- **Clássico:** ECDSA_P256 (128 bits)
- **Pós-quântico:** ML-DSA-44 (128 bits)
- **Balanceado:** true
- **Tempo de geração:** 4 ms (indicativo, execução única)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/par-recomendado-128/chave-publica-classica.der` | 91 | `5117e9c377eb3b1e9d120969d4fa5db1d4e9ec001ec6d75a14fd774a212f8052` |
| `01-geracao-chaves/par-recomendado-128/chave-publica-pqc.der` | 1334 | `fa1af162d2440bc0396fef0b6c1abcd437c251372d5bb58b452a340238ba6d19` |
| `01-geracao-chaves/par-recomendado-128/relatorio.txt` | 476 | `3a495e6cf48fdb57f2ed4dc9eb2bfe21d33d9df3896ad827f673265e55bb986a` |

### par-recomendado-192 — Par híbrido recomendado para 192 bits

- **Descrição:** ECDSA-384 + ML-DSA-65
- **Clássico:** ECDSA_P384 (192 bits)
- **Pós-quântico:** ML-DSA-65 (192 bits)
- **Balanceado:** true
- **Tempo de geração:** 2 ms (indicativo, execução única)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/par-recomendado-192/chave-publica-classica.der` | 120 | `a8ae321bd0bd8f18cb218378e025ad017983231a61cc97bc15886c7cbd0561a9` |
| `01-geracao-chaves/par-recomendado-192/chave-publica-pqc.der` | 1974 | `8418b117a980a1dd3c067d1445b747badf54120d606a38ea20a42e84b5204036` |
| `01-geracao-chaves/par-recomendado-192/relatorio.txt` | 476 | `822bf2a7f629266057e7d8e7bb0f6ddd216badf8b3aaa176fa1653ca6a76136e` |

### par-recomendado-256 — Par híbrido recomendado para 256 bits

- **Descrição:** ECDSA-521 + ML-DSA-87
- **Clássico:** ECDSA_P521 (256 bits)
- **Pós-quântico:** ML-DSA-87 (256 bits)
- **Balanceado:** true
- **Tempo de geração:** 3 ms (indicativo, execução única)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/par-recomendado-256/chave-publica-classica.der` | 158 | `68c96dc593929d28de152e3f16acfafb92b41fec529c041a8937753fca9647c6` |
| `01-geracao-chaves/par-recomendado-256/chave-publica-pqc.der` | 2614 | `fb51ff7a6026ef5e67ea812ff9f9049090c9f38c8adb9243a420f0eea6600a2f` |
| `01-geracao-chaves/par-recomendado-256/relatorio.txt` | 476 | `3383d52268b10eac839d68a2772a8260a27b858ab32004a1f82035b1857c0244` |

### resumo-pares — Pares recomendados por nível de segurança

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/resumo-pares/tabela.txt` | 310 | `f04d85a9b55a73a405ba560664c77a26c2ce115e1f26f6c7d05ed03d4d6ab463` |
| `01-geracao-chaves/resumo-pares/relatorio.txt` | 206 | `443baab7bfa5fe5d65b492c72de0f1d0f4951a23cca8cbd40bb010c97186aa5d` |

### rsa-2048 — Chave pública RSA_2048

- **Algoritmo:** RSA
- **Tamanho declarado:** 2048 bits
- **Nível de segurança:** 112 bits
- **Algoritmo de assinatura:** SHA256withRSA
- **OID:** 1.2.840.113549.1.1.1
- **SPKI codificado:** 294 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/rsa-2048/chave-publica.der` | 294 | `e2f71a5545942d1aeed527ff009f6a2fdcbbc290af7a758dd31eda636c023389` |
| `01-geracao-chaves/rsa-2048/chave-publica.txt` | 280 | `98a50a97c11bdf9080587390121d3d509f14344d0712cb22367b059362e7dea9` |
| `01-geracao-chaves/rsa-2048/chave-publica.hex` | 882 | `0725414321ecfea2a41badfee6bbc02d9b25519c7fce472a69f7841ff7c24f1f` |
| `01-geracao-chaves/rsa-2048/relatorio.txt` | 450 | `58f39f77331da62ce14e186d749a21e3c6736f4f7ee52940182d73231471a89a` |

### rsa-3072 — Chave pública RSA_3072

- **Algoritmo:** RSA
- **Tamanho declarado:** 3072 bits
- **Nível de segurança:** 128 bits
- **Algoritmo de assinatura:** SHA256withRSA
- **OID:** 1.2.840.113549.1.1.1
- **SPKI codificado:** 422 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/rsa-3072/chave-publica.der` | 422 | `78d2e1c562f27117fed0f313beb79898cc84a6e6bf2b94950a889d97580d6935` |
| `01-geracao-chaves/rsa-3072/chave-publica.txt` | 280 | `03246cb51ab6b4d36de65f11882a37da0b2ab67492a4ccd04d78bd69a12adbc6` |
| `01-geracao-chaves/rsa-3072/chave-publica.hex` | 1266 | `6489efa089e069b02f19e888d3b3b9fd6f6d24a85a61b4517dd77f3086f581e4` |
| `01-geracao-chaves/rsa-3072/relatorio.txt` | 450 | `eb35b171f05929e330113d56efd2a850e1d9a1e38d43aac1a576026f59905c16` |

### rsa-4096 — Chave pública RSA_4096

- **Algoritmo:** RSA
- **Tamanho declarado:** 4096 bits
- **Nível de segurança:** 152 bits
- **Algoritmo de assinatura:** SHA512withRSA
- **OID:** 1.2.840.113549.1.1.1
- **SPKI codificado:** 550 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/rsa-4096/chave-publica.der` | 550 | `c1f21cd04eed0825f98f173260402838bc6e610f50b988a7c4d19a24f16f6003` |
| `01-geracao-chaves/rsa-4096/chave-publica.txt` | 280 | `28edacc0038f58765464e4978d0c9a3f750df26580a28a4130dc6c6986f1fac5` |
| `01-geracao-chaves/rsa-4096/chave-publica.hex` | 1650 | `80bbd77853c72ae261d583408e8202d30a1b60562b3668f203116249a75b15d2` |
| `01-geracao-chaves/rsa-4096/relatorio.txt` | 450 | `b3d0fe65a3e731ddb7f697f1e054c98fc9f0ed1dd8b4344902ca677f309c91bc` |

### ecdsa-p256 — Chave pública ECDSA_P256

- **Algoritmo:** ECDSA
- **Tamanho declarado:** 256 bits
- **Nível de segurança:** 128 bits
- **Algoritmo de assinatura:** SHA256withECDSA
- **OID:** 1.2.840.10045.2.1
- **SPKI codificado:** 91 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ecdsa-p256/chave-publica.der` | 91 | `f152148432ce231e3ec2e781fab033587a292d9988aae9267b704b869730b475` |
| `01-geracao-chaves/ecdsa-p256/chave-publica.txt` | 272 | `7c58b436eefad17e39d4040ff18800d4b7a5815b1712548c20cf601fe76d8fad` |
| `01-geracao-chaves/ecdsa-p256/chave-publica.hex` | 273 | `efbcca55f240014dc50151f78bf0042470acd736dc9d469f8294bb8adecba98d` |
| `01-geracao-chaves/ecdsa-p256/relatorio.txt` | 453 | `a3990530b776a416aaf45a0b8d39c25cc05f4b4aa73d05818b475057f5c54260` |

### ecdsa-p384 — Chave pública ECDSA_P384

- **Algoritmo:** ECDSA
- **Tamanho declarado:** 384 bits
- **Nível de segurança:** 192 bits
- **Algoritmo de assinatura:** SHA384withECDSA
- **OID:** 1.2.840.10045.2.1
- **SPKI codificado:** 120 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ecdsa-p384/chave-publica.der` | 120 | `574e05360fe17fb21d6d0b0d70558c7ff9ca1a69fe19caaea6e04b0d1601903d` |
| `01-geracao-chaves/ecdsa-p384/chave-publica.txt` | 272 | `095eab03284efbc50d25f79d00529ddb9ed70f7b9069d5f995aa540274e8dc66` |
| `01-geracao-chaves/ecdsa-p384/chave-publica.hex` | 360 | `3a58d54808496b3cd38664db5b589a0cbabcc24f67075f299c245e84b4859ac5` |
| `01-geracao-chaves/ecdsa-p384/relatorio.txt` | 454 | `3503e0817b1c70c76fd95a6a0a2bd012e70d8c691b0098be2cccfa403a1000cf` |

### ecdsa-p521 — Chave pública ECDSA_P521

- **Algoritmo:** ECDSA
- **Tamanho declarado:** 521 bits
- **Nível de segurança:** 256 bits
- **Algoritmo de assinatura:** SHA512withECDSA
- **OID:** 1.2.840.10045.2.1
- **SPKI codificado:** 158 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ecdsa-p521/chave-publica.der` | 158 | `2afbf26f15ec28453d45cb90a74245c0378114899e0de492884f4f3223ace8d4` |
| `01-geracao-chaves/ecdsa-p521/chave-publica.txt` | 272 | `ed7409ae2b344d8cb47bba8b81979c31fe0850f52a66a6b771e6646d8eae9821` |
| `01-geracao-chaves/ecdsa-p521/chave-publica.hex` | 474 | `1e52fd2917fa1523237a4e2d5a0da2695b0802e282db801e64e857755ad958ec` |
| `01-geracao-chaves/ecdsa-p521/relatorio.txt` | 454 | `fdd4f8369eadf1007fc17e93c781fa39f08db08a7c60d9f598a127360157e7f0` |

### resumo-classicos — Tabela comparativa das variantes clássicas

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/resumo-classicos/tabela.txt` | 381 | `6beaf4b79f702e829c29df3366081036af23d3ae7b284d347430753ffaa32adc` |
| `01-geracao-chaves/resumo-classicos/relatorio.txt` | 135 | `ba604b989c0f1e49a7436dfc19e43487c336db1214957618bc5c3fcb99a0073f` |

## 03-autoridade-certificadora

### cadeia-com-ancora-trocada — Rejeição de cadeia cuja âncora foi substituída

- **DN das duas raízes:** CN=PQC Hybrid Root CA,O=TCC,C=BR (idêntico)
- **Cadeia legítima:** clássica=true, pqc=true
- **Cadeia com raiz impostora:** clássica=false, pqc=false

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `03-autoridade-certificadora/cadeia-com-ancora-trocada/raiz-legitima.der` | 5875 | `82f275dbe6ae6c78da5bd1f38758bee80a3a692835158c29acbb09a42de4f14e` |
| `03-autoridade-certificadora/cadeia-com-ancora-trocada/raiz-impostora.der` | 5874 | `98597b1ec20981d818a94f3d454cb4f29f29839bfd12e2da857e958d0ce388ee` |
| `03-autoridade-certificadora/cadeia-com-ancora-trocada/folha.der` | 5981 | `f3b125435aac5e1822144d9021dbd61639c8be058290c5701e8928c7d7a28e1a` |
| `03-autoridade-certificadora/cadeia-com-ancora-trocada/relatorio.txt` | 600 | `2304b82be3a0bc5eab4b5eff61c2bb579babdf056c58d1e4b4c778fee04dea72` |

### encadeamento-de-nomes — Encadeamento de nomes conforme RFC 5280 §6.1.3(a)(4)

- **Emissor declarado na folha:** C=BR,O=TCC,CN=PQC Hybrid Root CA
- **Sujeito da raiz legítima:** C=BR,O=TCC,CN=PQC Hybrid Root CA
- **Encadeia com a raiz legítima:** sim
- **Sujeito da outra CA:** C=BR,O=TCC,CN=Outra CA
- **Encadeia com a outra CA:** não

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `03-autoridade-certificadora/encadeamento-de-nomes/relatorio.txt` | 581 | `13e13f46935c176961ecca031a40a6cd9a9566ddf2a8354afb52221e5a5e3da8` |

### cadeia-tres-niveis — Cadeia híbrida raiz → sub-CA → entidade final

- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Raiz:** C=BR,O=TCC,CN=PQC Hybrid Root CA
- **Sub-CA:** C=BR,O=TCC,CN=PQC Hybrid Issuing CA
- **Entidade final:** C=BR,O=TCC,CN=secure.tcc.br
- **basicConstraints da raiz:** CA:TRUE, pathLen=1
- **basicConstraints da sub-CA:** CA:TRUE, pathLen=0
- **Validação clássica (PKIX):** true
- **Validação pós-quântica:** true
- **openssl verify:** aceita (exit 0)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `03-autoridade-certificadora/cadeia-tres-niveis/raiz.der` | 5878 | `e4a626df2c5a6a2200c017fd0c727297f88d123c26b4a384f4cb55cb8f4b54a4` |
| `03-autoridade-certificadora/cadeia-tres-niveis/subca.der` | 5965 | `50e0b5b35ab4a5c54dddff38196f862cad5d58e25bfd13bb3e589de5ac8ed563` |
| `03-autoridade-certificadora/cadeia-tres-niveis/folha.der` | 6024 | `f6aa5a106639808a3a131c9be4335f123ec34df1c995ebab0f603ec43f7b3f58` |
| `03-autoridade-certificadora/cadeia-tres-niveis/raiz.pem` | 8017 | `a9513df13df7301735608fbc054062d8b71fec4ad713760bcb06fddd6f4b15e1` |
| `03-autoridade-certificadora/cadeia-tres-niveis/subca.pem` | 8135 | `fae288c4c2cd8a4f55385935eca20d7907c66f60fd4474d80a3c99e63382d914` |
| `03-autoridade-certificadora/cadeia-tres-niveis/folha.pem` | 8212 | `b13d3a1b65b7981a9bee8860d792e760cf7ff2c6f7f9f88965f495ad6ce1d75a` |
| `03-autoridade-certificadora/cadeia-tres-niveis/cadeia.pem` | 24364 | `4ad5fb03a55e27ac8026cb159a36e1931fb5d8f6b92c1eac5d09110c9fea22e0` |
| `03-autoridade-certificadora/cadeia-tres-niveis/openssl-verify.txt` | 198 | `aad138c99d17133c89556d5dd114d28c0d69982aa2aac4be2128e2a9c7fd3ed3` |
| `03-autoridade-certificadora/cadeia-tres-niveis/relatorio.txt` | 791 | `cb57747a4ce4efe44127c27c32552720d1b9212417b7a68366901fd6a3d53321` |

## 09-politica-validacao

### integro — Íntegro

- **JDK PKIX (sem BouncyCastle):** aceita
- **openssl verify:** aceita
- **Biblioteca strict():** aceita
- **Biblioteca REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}:** aceita
- **Biblioteca CLASSICAL_ONLY:** aceita
- **Dimensão clássica (diagnóstico):** true
- **Dimensão pós-quântica (diagnóstico):** true
- **Motivos (REQUIRE_BOTH {65,87}):** —

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/integro/jdk-pkix.txt` | 36 | `be895871435f359e7243fd442ebecd023adccc7707fd0c881b25ff21eafa4c7a` |
| `09-politica-validacao/integro/openssl-verify.txt` | 27 | `2b87727f5b0387f9ad19be7819faae1a1a15125c44a83faefec156b35cf7e3e3` |
| `09-politica-validacao/integro/motivos-strict.txt` | 3 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `09-politica-validacao/integro/motivos-restrita.txt` | 3 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `09-politica-validacao/integro/folha.der` | 5987 | `06e41a4a87c43eb7342a3e9365f6df5131b29014b7aa5bb72fa07dd25a48d587` |
| `09-politica-validacao/integro/raiz.der` | 5871 | `c67f095983164077531c9548acbf1e0aabe3877f7f4ea81adab10dde96c77cdd` |
| `09-politica-validacao/integro/relatorio.txt` | 542 | `abd9e6b552df5739846503cb058bdcec947db5e3aa24241908fa8e98c79f8d29` |

### assinadores-misturados — Assinadores misturados (clássica da AC + ML-DSA do atacante)

- **JDK PKIX (sem BouncyCastle):** aceita
- **openssl verify:** aceita
- **Biblioteca strict():** rejeita
- **Biblioteca REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}:** rejeita
- **Biblioteca CLASSICAL_ONLY:** aceita
- **Dimensão clássica (diagnóstico):** true
- **Dimensão pós-quântica (diagnóstico):** false
- **Motivos (REQUIRE_BOTH {65,87}):** ALT_SIGNATURE_INVALID@0

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/assinadores-misturados/jdk-pkix.txt` | 36 | `be895871435f359e7243fd442ebecd023adccc7707fd0c881b25ff21eafa4c7a` |
| `09-politica-validacao/assinadores-misturados/openssl-verify.txt` | 27 | `2b87727f5b0387f9ad19be7819faae1a1a15125c44a83faefec156b35cf7e3e3` |
| `09-politica-validacao/assinadores-misturados/motivos-strict.txt` | 108 | `3c5f0850c05e6d1b7acf229b85c4fbf82a352f09c0cd3bd6a511bfa7953062ae` |
| `09-politica-validacao/assinadores-misturados/motivos-restrita.txt` | 108 | `3c5f0850c05e6d1b7acf229b85c4fbf82a352f09c0cd3bd6a511bfa7953062ae` |
| `09-politica-validacao/assinadores-misturados/folha.der` | 5988 | `5a7789f3e66a522d878f907c4e43a7d18e1bf61dd1b053e5da777f885ec7b01b` |
| `09-politica-validacao/assinadores-misturados/raiz.der` | 5871 | `c67f095983164077531c9548acbf1e0aabe3877f7f4ea81adab10dde96c77cdd` |
| `09-politica-validacao/assinadores-misturados/relatorio.txt` | 671 | `5a47d37c3a75c4455da24f4f2c999f7618d920ded0141839f37e6f18666a1d97` |

### stripping — Stripping (só clássico, chave da AC)

- **JDK PKIX (sem BouncyCastle):** aceita
- **openssl verify:** aceita
- **Biblioteca strict():** rejeita
- **Biblioteca REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}:** rejeita
- **Biblioteca CLASSICAL_ONLY:** aceita
- **Dimensão clássica (diagnóstico):** true
- **Dimensão pós-quântica (diagnóstico):** false
- **Motivos (REQUIRE_BOTH {65,87}):** ALT_EXTENSIONS_MISSING@0

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/stripping/jdk-pkix.txt` | 36 | `be895871435f359e7243fd442ebecd023adccc7707fd0c881b25ff21eafa4c7a` |
| `09-politica-validacao/stripping/openssl-verify.txt` | 27 | `2b87727f5b0387f9ad19be7819faae1a1a15125c44a83faefec156b35cf7e3e3` |
| `09-politica-validacao/stripping/motivos-strict.txt` | 118 | `802a1fa295a52a89df2cd4741a06b413f0334cb99c7ff9d1ccdcf36413afb1ef` |
| `09-politica-validacao/stripping/motivos-restrita.txt` | 118 | `802a1fa295a52a89df2cd4741a06b413f0334cb99c7ff9d1ccdcf36413afb1ef` |
| `09-politica-validacao/stripping/folha.der` | 650 | `d0c3f785513cfd4f4bf305c68de0752ca73e4c02384ff76b8cd50d6bee0269c8` |
| `09-politica-validacao/stripping/raiz.der` | 5871 | `c67f095983164077531c9548acbf1e0aabe3877f7f4ea81adab10dde96c77cdd` |
| `09-politica-validacao/stripping/relatorio.txt` | 625 | `fdd4d8c2f8b9beb482c4bdbb8ef453415fc70944beb4ee34ff3e8c82181b78a8` |

### algoritmo-fora-da-lista — Algoritmo alternativo fora da lista (ML-DSA-44)

- **JDK PKIX (sem BouncyCastle):** aceita
- **openssl verify:** aceita
- **Biblioteca strict():** aceita
- **Biblioteca REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}:** rejeita
- **Biblioteca CLASSICAL_ONLY:** aceita
- **Dimensão clássica (diagnóstico):** true
- **Dimensão pós-quântica (diagnóstico):** true
- **Motivos (REQUIRE_BOTH {65,87}):** ALT_ALGORITHM_NOT_ALLOWED@0, ALT_ALGORITHM_NOT_ALLOWED@1

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/algoritmo-fora-da-lista/jdk-pkix.txt` | 36 | `be895871435f359e7243fd442ebecd023adccc7707fd0c881b25ff21eafa4c7a` |
| `09-politica-validacao/algoritmo-fora-da-lista/openssl-verify.txt` | 27 | `2b87727f5b0387f9ad19be7819faae1a1a15125c44a83faefec156b35cf7e3e3` |
| `09-politica-validacao/algoritmo-fora-da-lista/motivos-strict.txt` | 3 | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `09-politica-validacao/algoritmo-fora-da-lista/motivos-restrita.txt` | 149 | `8b555a8a2fd2e838c01a8c0390740294acd109416e7cdabaa41391977951bec0` |
| `09-politica-validacao/algoritmo-fora-da-lista/folha.der` | 4396 | `bccbb4acfb4ddc1097ab0c20874123d3319c47b4affc38d9679dc03f32c399f2` |
| `09-politica-validacao/algoritmo-fora-da-lista/raiz.der` | 4281 | `c6f170a7c4c1e5c65a2dcca569aec0767ff3b7fe74894a033b1f1fa78f1bf2fa` |
| `09-politica-validacao/algoritmo-fora-da-lista/relatorio.txt` | 675 | `92050240870cdbaca3942eb0ab115e24e5ad2cac34576dec29be69db66260d63` |

### matriz — Matriz: verificadores legados × política da biblioteca

- **Versão do OpenSSL:** OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- **Política restrita:** REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/matriz/matriz.txt` | 1225 | `650093fa84d9f1b62593dfa85e41a10d68a055e2d420abac1620e73332243277` |
| `09-politica-validacao/matriz/relatorio.txt` | 574 | `d8232fb79c2a0be1cc7b0927f5d271a040a7a3a3402ceba97fac07afa4111894` |

## 08-provedor

### algoritmos-obrigatorios — Verificação de algoritmos obrigatórios na inicialização

- **Resultado:** aprovado, sem exceção
- **Comportamento em caso de ausência:** PQCHybridException nomeando os algoritmos faltantes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `08-provedor/algoritmos-obrigatorios/obrigatorios.txt` | 172 | `ce7c95e884f26ca1b85760fc5319f2775c16a97a0b90f363afb1718694ece191` |
| `08-provedor/algoritmos-obrigatorios/relatorio.txt` | 450 | `c5233b2eb2acd4296077cd42b05a79fa7e04b990277a438487b79be2e0bbef6e` |

### provedor-em-uso — Provedor criptográfico que respaldou a campanha

- **Nome:** BC
- **Versão:** 1.84
- **Informação:** BouncyCastle Security Provider v1.84
- **Serviços registrados:** 1624
- **Inicialização idempotente:** sim (dupla checagem sincronizada)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `08-provedor/provedor-em-uso/relatorio.txt` | 383 | `70df3eabc0e85f33d24515d461555715ef28caa8aaedd8475d068967ab61d0ab` |

### disponibilidade-algoritmos — Matriz de disponibilidade dos algoritmos do fluxo ativo

- **Variantes clássicas:** 6
- **Variantes pós-quânticas:** 3
- **Esquemas PQC no enum:** somente ML-DSA (FIPS 204)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `08-provedor/disponibilidade-algoritmos/matriz.txt` | 510 | `ab419cdc0462b78c30c066690a9caa601b9b3f11350ecb77741dde7c6e3baee7` |
| `08-provedor/disponibilidade-algoritmos/relatorio.txt` | 310 | `0382540eff4f4bef1c3b828e5a2844ad5cf4799fcb3b15b9488df3bac61adc9f` |

## Conferência de integridade

```sh
# a partir do diretorio evidencias/
sha256sum -c SHA256SUMS
```
