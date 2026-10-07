# Manifesto de evidência — validação do módulo

Gerado por `mvn test -Pvalidacao` em 2026-10-07T16:29:53.273217772-03:00.

Todo artefato listado abaixo é **material público** — certificados, requisições, chaves públicas e assinaturas. Nenhuma chave privada é gravada.

Ambiente completo em [`ambiente.txt`](ambiente.txt). Versão legível por máquina em [`manifesto.json`](manifesto.json).

## Resumo

- Casos executados: **52**
- Casos pulados: **0**
- Artefatos gravados: **214**
- Bytes totais: **484590**

## 05-assinatura-dados

### envelope-hibrido — Envelope de assinatura híbrida

- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Dados assinados:** 71 bytes
- **Envelope completo:** 3416 bytes
- **Prefixo de tamanho:** 4 bytes (big-endian)
- **Assinatura clássica:** 103 bytes
- **Assinatura ML-DSA-65:** 3309 bytes
- **Sobrecarga sobre a clássica isolada:** 33.2x

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `05-assinatura-dados/envelope-hibrido/dados-assinados.bin` | 71 | `438ac4ffc84f9b34b0a5ee67d4ca1c6bb8865b07f2fb4fbce363b5570037d5e9` |
| `05-assinatura-dados/envelope-hibrido/envelope.bin` | 3416 | `c7b486fb07a9b0b69ad9c5419b3ff1bbcda978994e69d2919da74e7ee1998d64` |
| `05-assinatura-dados/envelope-hibrido/assinatura-classica.bin` | 103 | `b7f2ba3da6dac75dfa283004366a9932b6e6d63eccb39be511162b5da3a1f664` |
| `05-assinatura-dados/envelope-hibrido/assinatura-pqc.bin` | 3309 | `768b3bcd9bc70569d9265412655b9ec092f554b9998c62c442e6cabe08b74891` |
| `05-assinatura-dados/envelope-hibrido/envelope.hex` | 10248 | `a9c87957d1fde925d3bffe9210272846bff9b41f6bf7b322345ed56fda832ad2` |
| `05-assinatura-dados/envelope-hibrido/relatorio-assinatura.txt` | 443 | `6bf2f54c3b71fcadb2ec6d4354cbf7e210971390d058118422aa5cc2fa256a04` |
| `05-assinatura-dados/envelope-hibrido/comparacao.txt` | 649 | `233be38c6944c54606f6c0b0cf76a5c97f3b4cf2dd3b6c596758c7f1eda060de` |
| `05-assinatura-dados/envelope-hibrido/estatisticas.txt` | 279 | `cbece83c664c9df48cb08b5a78561e99ef8cfcca42ca1daf0fe648fb32405946` |
| `05-assinatura-dados/envelope-hibrido/relatorio.txt` | 639 | `0f6c2d4c01ad30d0196026b9e51f987d40e66f04486a3ff8bbaa5727649b654c` |

### verificacao-apenas-classica — Conferência isolada da metade clássica

- **Verificação híbrida (E):** VÁLIDA
- **Verificação apenas clássica:** VÁLIDA
- **Algoritmo clássico:** ECDSA
- **Algoritmo pós-quântico:** ML-DSA-65

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `05-assinatura-dados/verificacao-apenas-classica/assinatura-classica.bin` | 104 | `eda0540dcce2f6c120c093dbd004a0cd7052663cf41829a7664c2b5cdbd4414a` |
| `05-assinatura-dados/verificacao-apenas-classica/assinatura-pqc.bin` | 3309 | `1f3aeacf411d1e437e95d78e70a48c5312fb69c37aef7f267becb9d5e9e706ac` |
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
| `05-assinatura-dados/separacao-por-contexto/envelope-ctx-faturamento.bin` | 3416 | `c59db0857bc5be6090f015729832d5f556c3388edd33e01ab5754ef039f2fed7` |
| `05-assinatura-dados/separacao-por-contexto/envelope-sem-contexto.bin` | 3417 | `4e1ab01732ffce91e67536de453e886b8a617cbdeddd159b2092716048c933e7` |
| `05-assinatura-dados/separacao-por-contexto/contexto-faturamento.bin` | 11 | `69e151e6bb68588d18413cd16d354f2844f433b343bd4f431e17713e28b33047` |
| `05-assinatura-dados/separacao-por-contexto/relatorio.txt` | 728 | `94997f18d8aee6e8386f4f31e0167825cf0787473b6f2fb695e63c5475744abd` |

### logica-e-adulteracao — Verificação sob lógica E e detecção de adulteração

- **Assinatura íntegra:** VÁLIDA
- **Dado com 1 bit alterado:** INVÁLIDA
- **Metade clássica corrompida:** INVÁLIDA
- **Metade pós-quântica corrompida:** INVÁLIDA

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `05-assinatura-dados/logica-e-adulteracao/envelope-integro.bin` | 3416 | `17f9c00700e987b55acb15a1bfcb47eb3a233ef4dde53fda3aff102f07ecffce` |
| `05-assinatura-dados/logica-e-adulteracao/envelope-classica-corrompida.bin` | 3416 | `0675561b7bb12c8a6acc3669499e44063a0f22c0de81402e12c24f3c79b7c250` |
| `05-assinatura-dados/logica-e-adulteracao/envelope-pqc-corrompida.bin` | 3416 | `e1d346e4356d14a88a997ce9dcd12d8c085120a4a2a9ee984d8383eadbf0cb8f` |
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
| `02-emissao-certificados/criticidade-compativel/certificado.der` | 5901 | `57620610b9050eacbd1e8bf873f592d2e91d0d397479eeac26b76a049319d045` |
| `02-emissao-certificados/criticidade-compativel/certificado.pem` | 8045 | `2d276176866c43a400e280c1b24585ff90d4405f9d90604b7edecb040ec7e5b4` |
| `02-emissao-certificados/criticidade-compativel/relatorio.txt` | 484 | `f532de771d99cf7d91dfe071ad7d2c3eaf84bab53b3c84f5834547401c08fed4` |

### criticidade-estrita — Extensões alternativas críticas

- **altSignatureExtensionsCritical:** true
- **Extensões críticas:** [2.5.29.19, 2.5.29.73, 2.5.29.74, 2.5.29.15]
- **Extensões não críticas:** [2.5.29.72, 2.5.29.35, 2.5.29.14, 2.5.29.37]
- **Consequência:** verificador conforme a RFC 5280 rejeita: impede downgrade silencioso

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/criticidade-estrita/certificado.der` | 5909 | `59d41e5ba0e602b974b682e51a103d2a8a7371eb022a0e1988cd186c7535a272` |
| `02-emissao-certificados/criticidade-estrita/certificado.pem` | 8058 | `94ccc68d00861982e783833e6659f129f33be158ce943a948e708505e16f0208` |
| `02-emissao-certificados/criticidade-estrita/relatorio.txt` | 465 | `5e9ce3e88be0b93cc07064ea8e6d759a786bb297d60e6973cec02493d0cb17f7` |

### nivel-128 — Certificado híbrido autoassinado de 128 bits

- **Par de algoritmos:** ECDSA-256 + ML-DSA-44
- **Algoritmo de assinatura:** SHA256WITHECDSA (OID 1.2.840.10045.4.3.2)
- **Sujeito:** C=BR,O=TCC,CN=nivel128.tcc.br
- **Número serial:** 773973963243214773579656581321352232345443770495
- **Certificado completo:** 4279 bytes (DER)
- **2.5.29.72 subjectAltPublicKeyInfo:** 1338 bytes, não crítica
- **2.5.29.73 altSignatureAlgorithm:** 15 bytes, não crítica
- **2.5.29.74 altSignatureValue:** 2429 bytes, não crítica

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/nivel-128/certificado.der` | 4279 | `149733c2a83b0bf6b84b8eff1e62a25d47be0daa543c1449b1db3b4cae557df3` |
| `02-emissao-certificados/nivel-128/certificado.pem` | 5852 | `4c323e8a06a9053e2df16d6425f99436de1f69beb229d8aea7ef9cdbb3fe8b54` |
| `02-emissao-certificados/nivel-128/inspecao.txt` | 1187 | `6ad0fa9718f2d69090f60230bc042ce2169095a6c64227f70e62ad1cb4544bab` |
| `02-emissao-certificados/nivel-128/extensao-2.5.29.72.der` | 1338 | `4be8491d44e4ef1863a948265a481a3c4fd7d908951f5fdb83f631f30da4be7f` |
| `02-emissao-certificados/nivel-128/extensao-2.5.29.73.der` | 15 | `20969a16b72e821aeab485aedc65b69ba6c8727a892ef27e49ec8638250d53b3` |
| `02-emissao-certificados/nivel-128/extensao-2.5.29.74.der` | 2429 | `e2ed37ee1916aff51d2fc92748ed20092258d5664eadd41b7cfb144a5d82db91` |
| `02-emissao-certificados/nivel-128/openssl-x509.txt` | 5573 | `69e2a41f8049b3c366a8f5f4a637dcf7993e26b0312355d0018fd70eef63f879` |
| `02-emissao-certificados/nivel-128/relatorio.txt` | 832 | `f84217d012ac63147b8573caa19798b1505b97d173a728c078691c37c59337ca` |

### nivel-192 — Certificado híbrido autoassinado de 192 bits

- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Algoritmo de assinatura:** SHA384WITHECDSA (OID 1.2.840.10045.4.3.3)
- **Sujeito:** C=BR,O=TCC,CN=nivel192.tcc.br
- **Número serial:** 537454775762250861283740376309646687681261538741
- **Certificado completo:** 5869 bytes (DER)
- **2.5.29.72 subjectAltPublicKeyInfo:** 1978 bytes, não crítica
- **2.5.29.73 altSignatureAlgorithm:** 15 bytes, não crítica
- **2.5.29.74 altSignatureValue:** 3318 bytes, não crítica

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/nivel-192/certificado.der` | 5869 | `f0e39af100f21a8b87dff7c02d65aab99a93a510fa977c02f2ffbfe2c5e829b2` |
| `02-emissao-certificados/nivel-192/certificado.pem` | 8005 | `c7a40155ce7208d17b8e73b6a43bc1d9551ad30366c3b5e4699cccf3a704a4f3` |
| `02-emissao-certificados/nivel-192/inspecao.txt` | 1188 | `955a7924df119bb78b5e3e8e28fce28cd316a4e49a0ef00abc5641c247c8f154` |
| `02-emissao-certificados/nivel-192/extensao-2.5.29.72.der` | 1978 | `eb0fc485e9ac75b04e7d053d2b634aadf473eb2e94d2475ef093a0d70d97e672` |
| `02-emissao-certificados/nivel-192/extensao-2.5.29.73.der` | 15 | `6d1e60231e16fdca46f0b1adf7631e110b33a1a2a59722bd745ce87f7fa6cf86` |
| `02-emissao-certificados/nivel-192/extensao-2.5.29.74.der` | 3318 | `9ab4ae9dbc75230f5aaa3e31b337510695ef04cb4355c48089eb4e2274658357` |
| `02-emissao-certificados/nivel-192/openssl-x509.txt` | 7356 | `3a546026a1464678e7abe8e90a1bab1d9fc656a4e30e784cc005b338bb2029a3` |
| `02-emissao-certificados/nivel-192/relatorio.txt` | 832 | `2f4e2e305e24b2cfea2c240be724dd575af04023eddacd3301fff7468f300101` |

### nivel-256 — Certificado híbrido autoassinado de 256 bits

- **Par de algoritmos:** ECDSA-521 + ML-DSA-87
- **Algoritmo de assinatura:** SHA512WITHECDSA (OID 1.2.840.10045.4.3.4)
- **Sujeito:** C=BR,O=TCC,CN=nivel256.tcc.br
- **Número serial:** 514692113249517244981716249891474809203952657337
- **Certificado completo:** 7901 bytes (DER)
- **2.5.29.72 subjectAltPublicKeyInfo:** 2618 bytes, não crítica
- **2.5.29.73 altSignatureAlgorithm:** 15 bytes, não crítica
- **2.5.29.74 altSignatureValue:** 4636 bytes, não crítica

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/nivel-256/certificado.der` | 7901 | `b40cd05014a63601a2cb7b8d1ab82ca4600e9c44644f8ee7d87792d2a009d3f8` |
| `02-emissao-certificados/nivel-256/certificado.pem` | 10755 | `4330af35964e30a115f78973e1716244350e60b9cdfe7e2aefb1745bed43f226` |
| `02-emissao-certificados/nivel-256/inspecao.txt` | 1188 | `3302a7843e5f9151f37217eb709573427ca5ae94e7981cb0563e6e47a17b2c5a` |
| `02-emissao-certificados/nivel-256/extensao-2.5.29.72.der` | 2618 | `985e48be9ca546967017a2dcc8e1a9186c42070a15106639d624292899c6e638` |
| `02-emissao-certificados/nivel-256/extensao-2.5.29.73.der` | 15 | `17157d037c92aa80c313d9e7f97572f675f98a9651ecb9d3ad77e3485b3d6b3d` |
| `02-emissao-certificados/nivel-256/extensao-2.5.29.74.der` | 4636 | `f5b604b728a0a7e3b8dd13435c8d00cafe345284406f898967691c9464b2b191` |
| `02-emissao-certificados/nivel-256/openssl-x509.txt` | 9587 | `7d6f8ca18b11c3db3ca33f85c88067b7574e14d1acaebdec4dd171a8d98dcb76` |
| `02-emissao-certificados/nivel-256/relatorio.txt` | 832 | `173c843206517cde809057d076256b839d34bb156da2b2d519d867b7550cfd87` |

### ordem-de-assinatura — Ordem de assinatura do modelo Catalyst

- **Assinatura alternativa sobre pre-TBS:** válida
- **Assinatura clássica sobre TBS:** válida

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/ordem-de-assinatura/tbs-certificate.der` | 5741 | `58047997663ccdd4896648d1084b0c4750be97d2bf20eecf48203ff84a763638` |
| `02-emissao-certificados/ordem-de-assinatura/relatorio.txt` | 625 | `d15bfa59105d1ab4b6b4aabf90008f143cd2075f1c09c1499f96cc301dcb2406` |

### layer1-signer-externo — Emissão via Layer 1 com ContentSigner fornecido externamente

- **Assinador clássico:** 1.2.840.10045.4.3.3
- **Assinador alternativo:** 2.16.840.1.101.3.4.3.18
- **Chave privada exigida pelo construtor:** nenhuma
- **Validação contra si mesmo:** aprovada nas duas dimensões

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `02-emissao-certificados/layer1-signer-externo/certificado.der` | 5892 | `1babd0edeac192d1c3a4832ada817598b77aa68a2a60b82851181543844b7422` |
| `02-emissao-certificados/layer1-signer-externo/certificado.pem` | 8033 | `1b6370a4eeb262771329c1e5c41e89af0e303954fce92a8ba8bb217ca3c46805` |
| `02-emissao-certificados/layer1-signer-externo/relatorio.txt` | 436 | `7053ab44d4322ffa2a9554d8a57b57d32ce027af9df767892d617d20ee799c92` |

## 04-requisicoes-csr

### csr-nivel-128 — CSR híbrida de 128 bits

- **Par de algoritmos:** ECDSA-256 + ML-DSA-44
- **Algoritmo da assinatura:** SHA256withECDSA
- **Tamanho:** 4054 bytes (DER)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/csr-nivel-128/requisicao.der` | 4054 | `40d6f7fdde9654834f5d73658c00c3635b2eeee0b90d08d88cafa1e15d517206` |
| `04-requisicoes-csr/csr-nivel-128/requisicao.pem` | 5563 | `452ceb992c902d10ed0a2eaf78bb1faf482fb31ad0977d77502fa6f1f4477dda` |
| `04-requisicoes-csr/csr-nivel-128/relatorio.txt` | 292 | `fd77cc615e3d95211104b443b468375be014e3b74f93d611898f3eaa98e617f1` |

### csr-nivel-192 — CSR híbrida de 192 bits

- **Par de algoritmos:** ECDSA-384 + ML-DSA-65
- **Algoritmo da assinatura:** SHA384withECDSA
- **Tamanho:** 5645 bytes (DER)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/csr-nivel-192/requisicao.der` | 5645 | `e8c69d292b9ed85423953b8570813c5593460866048da6f6a8e5b7b59ec8a15d` |
| `04-requisicoes-csr/csr-nivel-192/requisicao.pem` | 7716 | `5301aba6615d4d6d0abee9ef6b5c4a15e715473be123fbececfba3cd1fe916f2` |
| `04-requisicoes-csr/csr-nivel-192/relatorio.txt` | 292 | `324ec23436fc04b25770db2b1dd59c2a55b3baa18c25b6b7a425168d99bdfd61` |

### csr-nivel-256 — CSR híbrida de 256 bits

- **Par de algoritmos:** ECDSA-521 + ML-DSA-87
- **Algoritmo da assinatura:** SHA512withECDSA
- **Tamanho:** 7677 bytes (DER)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `04-requisicoes-csr/csr-nivel-256/requisicao.der` | 7677 | `e6b3608ce90a33d85c91231883265b7103c2e51d97795a5de506e335c1c1be84` |
| `04-requisicoes-csr/csr-nivel-256/requisicao.pem` | 10466 | `81765425c9a228db39060c8448fffb01c58d87db875346ffa25c730d92f91000` |
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
| `04-requisicoes-csr/csr-hibrida-192/requisicao.der` | 5648 | `7acc9830c0c0fa66a529e1beae89ce2b86a1bb23f188e8f308e96e2db413b063` |
| `04-requisicoes-csr/csr-hibrida-192/requisicao.pem` | 7720 | `cf089f83c71c63144a3be6bc0a0671665ef4cc303bf5713f127982624162bac5` |
| `04-requisicoes-csr/csr-hibrida-192/chave-publica-classica.der` | 120 | `c87bf4f0f8163950beba608e8e9b2a3568e2b4df8e6cc87ecfdd93efb078f98c` |
| `04-requisicoes-csr/csr-hibrida-192/chave-publica-pqc.der` | 1974 | `a15fff19a6280138382446a967e9173b8a57041a3cad4b5260a0d361c882bb0c` |
| `04-requisicoes-csr/csr-hibrida-192/openssl-req.txt` | 1435 | `b8f865254da8e282c8d677cddff719d1dece75c8e8697c25be6495ffeb9f682c` |
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

- **Certificado em DER:** 5871 bytes
- **Certificado em PEM:** 8005 bytes (base64 com envelope)
- **PEM decodificado == DER:** sim, byte a byte
- **DER reconstrói o certificado:** sim
- **SHA-256 do DER:** 08076388bd2702d2a06ac38d2d0e1d71d534c169b171e15fc445db25ba7befa6

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `07-exportacao-inspecao/pem-equivale-der/certificado.der` | 5871 | `08076388bd2702d2a06ac38d2d0e1d71d534c169b171e15fc445db25ba7befa6` |
| `07-exportacao-inspecao/pem-equivale-der/certificado.pem` | 8005 | `ab9dcdaa3ad99b9d76af3bb1b209123aef38a6a4911cbdb35096ed427cb9e883` |
| `07-exportacao-inspecao/pem-equivale-der/relatorio.txt` | 479 | `36fad372d27505f77638584fa0e62922cbadc5d7c6030ce655c21c798043ed4b` |

### relatorios-de-inspecao — Relatórios produzidos pelos inspetores

- **Reconhecido como híbrido:** true
- **Chave pública:** ECDSA Public Key [ECDSA-384]
- **Tamanho total das assinaturas:** 3.33 KB

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `07-exportacao-inspecao/relatorios-de-inspecao/inspecao-hibrida.txt` | 1189 | `db5c45e22234478c5c2574c6cc821fa91dce6c87c65bba64d4467aafaefbfd4a` |
| `07-exportacao-inspecao/relatorios-de-inspecao/certificado.txt` | 469 | `59ed268a0cbad54fed3d07d225a3210ffa4771c2f9240035a2a7015b1ff59cbe` |
| `07-exportacao-inspecao/relatorios-de-inspecao/certificado-compacto.txt` | 106 | `1e5dfc90af196ba05d188b5d21018e345a450b477263c5a29a9712b15fceb3a4` |
| `07-exportacao-inspecao/relatorios-de-inspecao/chave-publica-classica.txt` | 272 | `d1ab12cabf09630215f5aeeccedc55ec86c2b472abeb35c999b2e1b22330c657` |
| `07-exportacao-inspecao/relatorios-de-inspecao/chave-publica-pqc.txt` | 224 | `48e97bd52986339c7411918c17c57eeb2bb8d5b5443166fdc6af7d9e02d80d45` |
| `07-exportacao-inspecao/relatorios-de-inspecao/assinaturas.txt` | 443 | `4b042eb68c3c01a8e5d6421777817cc4ea0e72c67d6768c38704e6b5bbc797d6` |
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
| `06-validacao/cadeia-duas-dimensoes/folha.der` | 5980 | `41f74d51a7d7aca65950ccebfa56fce075448d058e183f02c5ae725affa21534` |
| `06-validacao/cadeia-duas-dimensoes/raiz.der` | 5873 | `caf02ee54208e07b4f378cf626ebc1f2340a26891514ee2b3e4f63651c27a56e` |
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
| `06-validacao/modos-de-falha/certificado-sem-extensoes.der` | 552 | `b5c908582587c4681fd53417104dd049379d2aeac1913fcdd7834d18cd45a48d` |
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
| `06-validacao/caminho-feliz/folha.der` | 5977 | `bef6a9bb13218e85ebf9f4d9908b88978ad1e488ce0982dd762e1cad06b47da9` |
| `06-validacao/caminho-feliz/emissor.der` | 5873 | `4ba59e4a2d3219b3bbf75b5388f2b5072533279d8ae3280000b2b78d315fcc9e` |
| `06-validacao/caminho-feliz/relatorio.txt` | 541 | `c3e655ec232b665b5fa5495ff2344b7f42e227c89adcbfd6d1bbc34423f332ce` |

## 01-geracao-chaves

### ml-dsa-44 — Chave pública ML-DSA-44

- **Nível de segurança:** 128 bits
- **OID:** 2.16.840.1.101.3.4.3.17
- **Chave crua (FIPS 204):** 1312 bytes
- **SPKI codificado:** 1334 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ml-dsa-44/chave-publica.der` | 1334 | `c0d5a2947c6381f2ad530e48b5c6e0264e1110aeee439efc8ee7ce91e3651998` |
| `01-geracao-chaves/ml-dsa-44/chave-publica.hex` | 4002 | `49e959aebd62f0c6134e12dd22e449f59e007edae93b1c7a6b928b60f589088d` |
| `01-geracao-chaves/ml-dsa-44/relatorio.txt` | 339 | `f6aa72c84e0499b8a2165192bef7f5e24af310926750ceab70d0d76847a21812` |

### ml-dsa-65 — Chave pública ML-DSA-65

- **Nível de segurança:** 192 bits
- **OID:** 2.16.840.1.101.3.4.3.18
- **Chave crua (FIPS 204):** 1952 bytes
- **SPKI codificado:** 1974 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ml-dsa-65/chave-publica.der` | 1974 | `2e4650eaf74d491dd4bb97b33c59f6659a61dd754d1047609fd4eafd077b6619` |
| `01-geracao-chaves/ml-dsa-65/chave-publica.hex` | 5922 | `9bc25041ab5c19faf1308bf2a8f995a26a2b367fc5817669f019796df052b1bd` |
| `01-geracao-chaves/ml-dsa-65/relatorio.txt` | 339 | `f9cf080e228b1e1a611bfc487a9dbafbdd7a2a7a01dbea896efb4fd1cc3a8419` |

### ml-dsa-87 — Chave pública ML-DSA-87

- **Nível de segurança:** 256 bits
- **OID:** 2.16.840.1.101.3.4.3.19
- **Chave crua (FIPS 204):** 2592 bytes
- **SPKI codificado:** 2614 bytes

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/ml-dsa-87/chave-publica.der` | 2614 | `a235c3b603c294b5c46951952b73d73b931587f000a6e13502def653b58a77a9` |
| `01-geracao-chaves/ml-dsa-87/chave-publica.hex` | 7842 | `56ae115c234aee638e572d0168f207e048b01041b5bb013da8ff5375d11a9b3b` |
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
- **Tempo de geração:** 5 ms (indicativo, execução única)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/par-recomendado-128/chave-publica-classica.der` | 91 | `16b1451a5983868def06fd36e7b678d597e908b6c4c44bb0553ca36f819d5b88` |
| `01-geracao-chaves/par-recomendado-128/chave-publica-pqc.der` | 1334 | `616b61e85162e2a02eab3b4e74a41d1747f21b6465fc81b1cd667441c9fae5a8` |
| `01-geracao-chaves/par-recomendado-128/relatorio.txt` | 476 | `d44de0828c233aea19e1b6f4e48e12179447f3fdd66d30f64181fb3393b0d3b8` |

### par-recomendado-192 — Par híbrido recomendado para 192 bits

- **Descrição:** ECDSA-384 + ML-DSA-65
- **Clássico:** ECDSA_P384 (192 bits)
- **Pós-quântico:** ML-DSA-65 (192 bits)
- **Balanceado:** true
- **Tempo de geração:** 8 ms (indicativo, execução única)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/par-recomendado-192/chave-publica-classica.der` | 120 | `2fa0f3eff6e88d9ddc7ef25b40f5712dafc03882af09e1f756e70a8309ac000c` |
| `01-geracao-chaves/par-recomendado-192/chave-publica-pqc.der` | 1974 | `f58a39483825e1f0cfabec6b9a4643120256e1d3d569d2b0104e60dc3c6e5370` |
| `01-geracao-chaves/par-recomendado-192/relatorio.txt` | 476 | `489831a94f81288def6d6a766acc0e35f94a4248bdc8d8159908c11d95cd8542` |

### par-recomendado-256 — Par híbrido recomendado para 256 bits

- **Descrição:** ECDSA-521 + ML-DSA-87
- **Clássico:** ECDSA_P521 (256 bits)
- **Pós-quântico:** ML-DSA-87 (256 bits)
- **Balanceado:** true
- **Tempo de geração:** 32 ms (indicativo, execução única)

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `01-geracao-chaves/par-recomendado-256/chave-publica-classica.der` | 158 | `503e93167f3960f1e51be772e480c2ad635d3db3d517201d57f5b885a57dd549` |
| `01-geracao-chaves/par-recomendado-256/chave-publica-pqc.der` | 2614 | `a720412e3d9bd2cb78743a745841e60229890d7ad27101d67389a621df642c97` |
| `01-geracao-chaves/par-recomendado-256/relatorio.txt` | 477 | `1b3bea69e250597a75eda6d1e4af7c4d329693724bbb1ca1dfaa27f5232773df` |

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
| `01-geracao-chaves/rsa-2048/chave-publica.der` | 294 | `c7aa44a8dae91e20ecf72f0a3b48d0db270a8fa19c90eb7a9680c90d9ab39daf` |
| `01-geracao-chaves/rsa-2048/chave-publica.txt` | 280 | `5c2ccf3a69176900bdd157293406e45ce6e005393fd4c1ecb508a0167cc29125` |
| `01-geracao-chaves/rsa-2048/chave-publica.hex` | 882 | `60b78d89bc232c3e6e87b8c7d045e403e1d38e7d0597de34c3da805f06126006` |
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
| `01-geracao-chaves/rsa-3072/chave-publica.der` | 422 | `9e48c9397f4fc6c33260f2ae459851d63c7bcc4cb78772b0a53d805638619756` |
| `01-geracao-chaves/rsa-3072/chave-publica.txt` | 280 | `d54e5460026b54be41c2caf2339e37d21ae4a0fb7bb44d6fe777a6a6d7e4e139` |
| `01-geracao-chaves/rsa-3072/chave-publica.hex` | 1266 | `18dffd59d7feaacc1983a8592effa9f5800128eb0c050d83c2756510c538ea6d` |
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
| `01-geracao-chaves/rsa-4096/chave-publica.der` | 550 | `ec9a3cbe48a69f5956d53362c23c2c7dc7f70682c5de028aff46492e5e19ccf4` |
| `01-geracao-chaves/rsa-4096/chave-publica.txt` | 280 | `d4c185eaff2ee7add3e38190daa6b9d5310428b96c07f0a1c7cafc23c54890a2` |
| `01-geracao-chaves/rsa-4096/chave-publica.hex` | 1650 | `4219548c36c923dadd770dc32643974109cdcef06a1c7d024337c4934b851215` |
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
| `01-geracao-chaves/ecdsa-p256/chave-publica.der` | 91 | `d6268d10820b8df23222ba5bb6c4220956c8b8834036471e668436194c9530bd` |
| `01-geracao-chaves/ecdsa-p256/chave-publica.txt` | 272 | `f254a2365d57b657116f4c4ab098e1ecfe5b7f749ab3a4451be05c3d48306446` |
| `01-geracao-chaves/ecdsa-p256/chave-publica.hex` | 273 | `bbf874f44c26e1c20d92fc8dba27ae9e25acc8fca8e5d8d26c3deeb88a3e9b3d` |
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
| `01-geracao-chaves/ecdsa-p384/chave-publica.der` | 120 | `c8a2f1c860a1c164cd820285ba7664a9a24e4d49b15d8083a85ad1145d7614c5` |
| `01-geracao-chaves/ecdsa-p384/chave-publica.txt` | 272 | `306347eb6241d63e643db9de06a75810dd78175c310cce3fbc761de3f13f1446` |
| `01-geracao-chaves/ecdsa-p384/chave-publica.hex` | 360 | `10bfb35d283ec5c24e00667a92922d2fc56b4e2344ffed0894f93de74dd9e124` |
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
| `01-geracao-chaves/ecdsa-p521/chave-publica.der` | 158 | `6bb1321b6e87a4e4564dcd69aafa8fe43718d086a85bd2efb46ff54621b7e224` |
| `01-geracao-chaves/ecdsa-p521/chave-publica.txt` | 272 | `3675aeef546cf3f94ac876ccf0a1f34e41c122262785cbd6c5d017fb8fa2adc5` |
| `01-geracao-chaves/ecdsa-p521/chave-publica.hex` | 474 | `4568dffaca934ce80c6c4b93d6f3e82fac5d66421c1d6dcab3a9ef0fd4f668ab` |
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
| `03-autoridade-certificadora/cadeia-com-ancora-trocada/raiz-legitima.der` | 5874 | `28ee22fd09fb3184285f892498de034bde465f2f44dd0a4c44f9db535993cccd` |
| `03-autoridade-certificadora/cadeia-com-ancora-trocada/raiz-impostora.der` | 5874 | `72c83a9aacd082f12ee874af8c947141b7a0425ee60cae3f8e7a0083f681300b` |
| `03-autoridade-certificadora/cadeia-com-ancora-trocada/folha.der` | 5982 | `c848ae470231ce962c8a3421bc8f23f189609697a560eff14905805cae8f0424` |
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
| `03-autoridade-certificadora/cadeia-tres-niveis/raiz.der` | 5878 | `bea21ce0d00359e60890e8dd9bd381b753bbe4775dd1dab671a3aa9018cb6bdf` |
| `03-autoridade-certificadora/cadeia-tres-niveis/subca.der` | 5965 | `997d226a84700f0736f302ead3d38a615204bd1bb5d5ef4d9189645cf6259957` |
| `03-autoridade-certificadora/cadeia-tres-niveis/folha.der` | 6022 | `538b4930524ea9d07f0173ffd87977f234c310dc626e843c70da42e58184405f` |
| `03-autoridade-certificadora/cadeia-tres-niveis/raiz.pem` | 8017 | `a2c3a7e1bced3d7dbe220801f1bb966bf54bc95ad47aabb703399b35a57bdbac` |
| `03-autoridade-certificadora/cadeia-tres-niveis/subca.pem` | 8135 | `f57916f1208c2c77abb4d039264c25f8d2dc1be4cbcfc441ff7145d350dd1d0a` |
| `03-autoridade-certificadora/cadeia-tres-niveis/folha.pem` | 8212 | `6483aef7cd83aa4fbdbf8d0a0a7c8cbca2ba66ad400032d2a4fb6958e8e8f98e` |
| `03-autoridade-certificadora/cadeia-tres-niveis/cadeia.pem` | 24364 | `1c530d18da777ec0902f7a587382d4637f7a4be75bebb6301e908884d5d7d967` |
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
| `09-politica-validacao/integro/folha.der` | 5988 | `b3865cc6a68bf51dbfea9f35c41b6c130df52fbdc01d8f43b0a5214c965a6ac7` |
| `09-politica-validacao/integro/raiz.der` | 5869 | `768fcee6454387dc6d7257acbd2d5be3717fbaee0a60c3038ebf52acc37d1d91` |
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
| `09-politica-validacao/assinadores-misturados/folha.der` | 5986 | `bd97bd8ae4b04e27ba904163b2d3c7a0b3bc050b26e17e9dfb2e49f78b2ce9c7` |
| `09-politica-validacao/assinadores-misturados/raiz.der` | 5869 | `768fcee6454387dc6d7257acbd2d5be3717fbaee0a60c3038ebf52acc37d1d91` |
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
| `09-politica-validacao/stripping/folha.der` | 648 | `4275f4c99e2b00809aeb1f66ea865efacf70e527333d83b038449748d103fb30` |
| `09-politica-validacao/stripping/raiz.der` | 5869 | `768fcee6454387dc6d7257acbd2d5be3717fbaee0a60c3038ebf52acc37d1d91` |
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
| `09-politica-validacao/algoritmo-fora-da-lista/folha.der` | 4398 | `e9a59f3af6c2331caa656c8b17ba8a9f08106b4e699e98331419fdb9e2e7c11a` |
| `09-politica-validacao/algoritmo-fora-da-lista/raiz.der` | 4282 | `8c56003d61d7159e93353e8f487d1b27b5d39ca19b5e98e37fa0954f4637905f` |
| `09-politica-validacao/algoritmo-fora-da-lista/relatorio.txt` | 675 | `92050240870cdbaca3942eb0ab115e24e5ad2cac34576dec29be69db66260d63` |

### assinatura-classica-invalida — Assinatura clássica inválida (clássica do atacante + ML-DSA da AC)

- **JDK PKIX (sem BouncyCastle):** rejeita
- **openssl verify:** rejeita
- **Biblioteca strict():** rejeita
- **Biblioteca REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}:** rejeita
- **Biblioteca CLASSICAL_ONLY:** rejeita
- **Dimensão clássica (diagnóstico):** false
- **Dimensão pós-quântica (diagnóstico):** true
- **Motivos (REQUIRE_BOTH {65,87}):** CLASSICAL_PATH_INVALID@0

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/assinatura-classica-invalida/jdk-pkix.txt` | 51 | `f02574985de386a6f17cdb5049345197a37904f50b4dd5b40d424886099596d3` |
| `09-politica-validacao/assinatura-classica-invalida/openssl-verify.txt` | 267 | `6ee20eca90be5a0d4009fa3cdc2020b5d252ef64142c7ed88794d0e06ade0e10` |
| `09-politica-validacao/assinatura-classica-invalida/motivos-strict.txt` | 82 | `08c7f7f95851e82114f0449d16d2318542086f15996d6eab6ea6614b0ef77590` |
| `09-politica-validacao/assinatura-classica-invalida/motivos-restrita.txt` | 82 | `08c7f7f95851e82114f0449d16d2318542086f15996d6eab6ea6614b0ef77590` |
| `09-politica-validacao/assinatura-classica-invalida/folha.der` | 5987 | `9649414f929e7bc0fbebaaa7fc29b6fff68f636d266f6f69ec6773a3daa16d90` |
| `09-politica-validacao/assinatura-classica-invalida/raiz.der` | 5869 | `768fcee6454387dc6d7257acbd2d5be3717fbaee0a60c3038ebf52acc37d1d91` |
| `09-politica-validacao/assinatura-classica-invalida/relatorio.txt` | 689 | `41382af32f67fa1480ed39d286bafbacd0ca1d7ad8217e12c7f5207c923885e9` |

### emissor-sem-chave-alternativa — Emissor sem chave alternativa (AC só clássica)

- **JDK PKIX (sem BouncyCastle):** aceita
- **openssl verify:** aceita
- **Biblioteca strict():** rejeita
- **Biblioteca REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}:** rejeita
- **Biblioteca CLASSICAL_ONLY:** aceita
- **Dimensão clássica (diagnóstico):** true
- **Dimensão pós-quântica (diagnóstico):** false
- **Motivos (REQUIRE_BOTH {65,87}):** ISSUER_ALT_KEY_MISSING@0, ALT_EXTENSIONS_MISSING@1

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/emissor-sem-chave-alternativa/jdk-pkix.txt` | 36 | `be895871435f359e7243fd442ebecd023adccc7707fd0c881b25ff21eafa4c7a` |
| `09-politica-validacao/emissor-sem-chave-alternativa/openssl-verify.txt` | 27 | `2b87727f5b0387f9ad19be7819faae1a1a15125c44a83faefec156b35cf7e3e3` |
| `09-politica-validacao/emissor-sem-chave-alternativa/motivos-strict.txt` | 196 | `331d6a212495906380bd9dffe76541937ef8f237bb23ae6982a52bd228198ef3` |
| `09-politica-validacao/emissor-sem-chave-alternativa/motivos-restrita.txt` | 196 | `331d6a212495906380bd9dffe76541937ef8f237bb23ae6982a52bd228198ef3` |
| `09-politica-validacao/emissor-sem-chave-alternativa/folha.der` | 5986 | `07de244de1f7ab418db4a97ea808a3616b9f0e2dffdb0ffbede421d7f98e254b` |
| `09-politica-validacao/emissor-sem-chave-alternativa/raiz.der` | 532 | `569fd181dd75909e64910a31db82348361fdbf475cb856a0bf80485ac9198a9e` |
| `09-politica-validacao/emissor-sem-chave-alternativa/relatorio.txt` | 671 | `56f9e9eaa40d18218c15df1c9419cbf77e15edb8f36f93507517f76429d496ef` |

### matriz — Matriz: verificadores legados × política da biblioteca

- **Versão do OpenSSL:** OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- **Política restrita:** REQUIRE_BOTH {ML-DSA-65, ML-DSA-87}

| Artefato | Bytes | SHA-256 |
|---|---:|---|
| `09-politica-validacao/matriz/matriz.txt` | 1684 | `5d63788db93122c59023ed80362a8c661092a417da3dd0952434ddfd577e6fe8` |
| `09-politica-validacao/matriz/relatorio.txt` | 610 | `5351e116826a32d22e725b1b932a956f5bfc19d9e13d5b288912b3b6d1ac29ec` |

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
