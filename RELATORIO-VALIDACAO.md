# Relatório de validação do módulo

**Biblioteca:** *PQC Hybrid Certificates* `1.0.0-BETA` (`pqc-migration-kit`)
**Base analisada:** `evidencias/` — 174 arquivos, 1,2 MB, 45 casos de evidência
**Execução analisada:** 2026-09-09T22:55:11-03:00 (Java 21.0.11 Temurin · Bouncy Castle 1.84 · OpenSSL 3.0.13 · Linux WSL2)
**Nota:** todos os números deste relatório são desta execução específica, identificada em `evidencias/manifesto.json`. Regerar a campanha altera os bytes (chaves e assinaturas são aleatórias; a assinatura ECDSA em DER varia 102–104 bytes), mas não as conclusões.
**Commit:** `b3794bc`, com alterações não commitadas na árvore de trabalho

---

## 1. Escopo e método

A campanha (`mvn test -Pvalidacao`) percorre as 8 áreas funcionais descritas no resumo do
módulo. Cada caso **assegura** a propriedade com asserções e **grava** os bytes que a
sustentam. A distinção importa: um gerador de relatórios produziria os mesmos arquivos mesmo
com o código quebrado; aqui, uma regressão faz a campanha falhar antes de escrever evidência
enganosa.

27 métodos de teste produziram 45 casos, 0 falhas, 0 pulados. Integridade conferida:
`sha256sum -c SHA256SUMS` → **170/170 OK** (os 4 arquivos restantes são os próprios manifestos,
que não podem se auto-referenciar).

A análise abaixo foi feita **sobre os artefatos gravados**, com ferramentas externas à
biblioteca (`openssl x509`, `openssl req`, `openssl verify`, `openssl asn1parse`, `stat`,
`sha256sum`), não sobre a saída da própria suíte.

---

## 2. Veredito

| Área | Resultado |
|---|---|
| 1. Geração de chaves | Conforme. 9 variantes, tamanhos batem com FIPS 204 e com os padrões clássicos |
| 2. Emissão de certificados | Conforme. Ordem Catalyst observável; criticidade parametrizável funcionando |
| 3. Autoridade certificadora | Conforme. Cadeia de 3 níveis válida nas duas dimensões e aceita externamente |
| 4. Requisições PKCS#10 | Conforme. Assinatura própria conferida por ferramenta externa |
| 5. Assinatura de dados | Conforme. Lógica E e separação de domínio comprovadas |
| 6. Validação | Conforme. Caminho feliz e 4 modos de falha comportam-se como especificado |
| 7. Exportação e inspeção | Conforme. PEM ≡ DER byte a byte |
| 8. Provedor | Conforme. BC 1.84, 1624 serviços, todos os algoritmos do fluxo disponíveis |

Nenhum defeito de comportamento foi encontrado na análise. As divergências relatadas na
seção 6 são entre a **evidência** e o **texto do TCC**, não no código.

---

## 3. Análise quantitativa

### 3.1 Chaves públicas

Todos os valores em bytes, medidos no `SubjectPublicKeyInfo` codificado em DER
(`evidencias/01-geracao-chaves/`).

| Variante | SPKI (DER) | Chave crua (padrão) | Sobrecarga do envelope |
|---|---:|---:|---:|
| ECDSA P-256 | 91 | — | — |
| ECDSA P-384 | 120 | — | — |
| ECDSA P-521 | 158 | — | — |
| RSA-2048 | 294 | — | — |
| RSA-3072 | 422 | — | — |
| RSA-4096 | 550 | — | — |
| ML-DSA-44 | 1.334 | 1.312 | 22 |
| ML-DSA-65 | 1.974 | 1.952 | 22 |
| ML-DSA-87 | 2.614 | 2.592 | 22 |

As chaves cruas de ML-DSA correspondem exatamente ao FIPS 204. A sobrecarga do envelope DER é
**constante em 22 bytes** nas três variantes — o `AlgorithmIdentifier` mais o invólucro
`BIT STRING`, cujo tamanho não varia porque os três OIDs têm o mesmo comprimento.

### 3.2 Certificados híbridos

Certificados autoassinados, um por nível (`evidencias/02-emissao-certificados/`).

| Nível | Par | Certificado | ext 72 | ext 73 | ext 74 | Catalyst / total |
|---|---|---:|---:|---:|---:|---:|
| 128 | ECDSA-256 + ML-DSA-44 | 4.278 | 1.338 | 15 | 2.429 | **88%** |
| 192 | ECDSA-384 + ML-DSA-65 | 5.868 | 1.978 | 15 | 3.318 | **90%** |
| 256 | ECDSA-521 + ML-DSA-87 | 7.902 | 2.618 | 15 | 4.636 | **91%** |

As três extensões Catalyst respondem por **88% a 91% do certificado**. O restante — campos
tradicionais, extensões PKIX convencionais e a assinatura clássica — cabe em 496 a 633 bytes.

**Sobrecargas DER constantes**, verificadas nos três níveis:

- `2.5.29.72` = SPKI da chave alternativa **+ 4 bytes**
- `2.5.29.74` = assinatura ML-DSA crua **+ 9 bytes**
- `2.5.29.73` = **15 bytes fixos** em qualquer nível

A regularidade nos três níveis é, em si, evidência de que a construção das extensões não
depende do nível de segurança.

### 3.3 Custo real da hibridização

A campanha produziu, no caso de falha da área 6, um certificado com o **mesmo par de chaves e
o mesmo sujeito, porém sem as extensões Catalyst**. Isso dá uma linha de base medida, não
estimada:

| Certificado ECDSA P-384 | Bytes |
|---|---:|
| Clássico (sem Catalyst) | **551** |
| Híbrido (com ML-DSA-65) | **5.868** |
| Crescimento | **10,6×** (+5.317 bytes) |

Para a cadeia de três níveis (`evidencias/03-autoridade-certificadora/cadeia-tres-niveis/`):
raiz 5.877 + sub-CA 5.966 + folha 6.021 = **17.864 bytes**. É o volume que um *handshake* TLS
transportaria a cada conexão que apresentasse a cadeia completa.

### 3.4 Assinatura de dados avulsos

Envelope `[4 bytes de prefixo][clássica][PQC]` para ECDSA-P384 + ML-DSA-65, sobre 71 bytes de
dados (`evidencias/05-assinatura-dados/envelope-hibrido/`):

| Componente | Bytes |
|---|---:|
| Prefixo de tamanho | 4 |
| Assinatura ECDSA P-384 | 102 |
| Assinatura ML-DSA-65 | 3.309 |
| **Envelope total** | **3.415** |

A metade pós-quântica representa 96,9% do envelope. Frente a uma assinatura clássica isolada,
o custo é de **33,5×**.

O prefixo explícito de tamanho não é decorativo: a assinatura ECDSA é de comprimento variável
(102 bytes nesta execução; execuções anteriores produziram 103, conforme a codificação DER
dos inteiros `r` e `s`), de
modo que uma divisão por posição fixa não recuperaria as duas metades.

---

## 4. Confirmação por ferramentas externas

O ponto mais forte da evidência é o que foi confirmado **fora** da biblioteca.

**Seleção de digest.** O `openssl x509` decodifica os três certificados e reporta
`ecdsa-with-SHA256`, `ecdsa-with-SHA384` e `ecdsa-with-SHA512` para os níveis 128, 192 e 256.
Como o OpenSSL não conhece esta biblioteca, isso confirma de forma independente que o digest
acompanha a força da chave.

**Compatibilidade retroativa.** A cadeia de três níveis é aceita por um verificador que não
entende Catalyst:

```
$ openssl verify -CAfile raiz.pem -untrusted subca.pem folha.pem
folha.pem: OK
```

**Extensões desconhecidas, porém toleradas.** O OpenSSL não tem nome para os OIDs Catalyst e
os imprime crus, sem interpretá-los:

```
X509v3 Key Usage: critical
X509v3 Basic Constraints: critical
2.5.29.72:
2.5.29.73:
2.5.29.74:
```

É exatamente a demonstração pretendida: o verificador legado enxerga as extensões, não as
compreende, e ainda assim aceita o certificado pela assinatura clássica.

**Criticidade como ponto de controle.** Nos dois modos emitidos, o OpenSSL confirma o efeito:

| Modo | 2.5.29.72 | 2.5.29.73 | 2.5.29.74 |
|---|---|---|---|
| Compatível (padrão) | não crítica | não crítica | não crítica |
| Estrita | não crítica | **critical** | **critical** |

O custo do modo estrito é de apenas 5 bytes por certificado (5.903 → 5.908, mesmo sujeito) — o compromisso é
de política de migração, não de espaço.

**OIDs de algoritmo.** `openssl asn1parse` sobre a extensão `2.5.29.73` dos três níveis:

| Nível | Conteúdo DER | OID | Algoritmo |
|---|---|---|---|
| 128 | `300B0609 608648016503040311` | 2.16.840.1.101.3.4.3.**17** | ML-DSA-44 |
| 192 | `300B0609 608648016503040312` | 2.16.840.1.101.3.4.3.**18** | ML-DSA-65 |
| 256 | `300B0609 608648016503040313` | 2.16.840.1.101.3.4.3.**19** | ML-DSA-87 |

Os três têm 15 bytes, mas o conteúdo difere no último octeto do OID, conforme o FIPS 204.

**Requisições PKCS#10.** O `openssl req -verify` responde
`Certificate request self-signature verify OK`, e o decode mostra os três atributos Catalyst
presentes e não interpretados:

```
Attributes:
    2.5.29.73  :unable to print attribute
    2.5.29.72  :unable to print attribute
    2.5.29.74  :unable to print attribute
```

Vale registrar que a CSR carrega os **três** OIDs, não apenas a chave alternativa: ela replica
o modelo de assinatura alternativa do certificado.

---

## 5. Comportamento sob condições adversas

**Lógica E** (`evidencias/05-assinatura-dados/logica-e-adulteracao/`):

| Condição | Resultado |
|---|---|
| Assinatura íntegra | VÁLIDA |
| Um bit alterado no dado | INVÁLIDA |
| Apenas a metade clássica corrompida | INVÁLIDA |
| Apenas a metade pós-quântica corrompida | INVÁLIDA |

Comprometer uma única metade já invalida o conjunto — a propriedade que sustenta a defesa em
profundidade.

**Separação de domínio pelo contexto FIPS 204:**

| Cenário | Resultado |
|---|---|
| Assinado e verificado com `"faturamento"` | VÁLIDA |
| Assinado com `"faturamento"`, verificado com `"auditoria"` | INVÁLIDA |
| Assinado com `"faturamento"`, verificado sem contexto | INVÁLIDA |
| Assinado sem contexto, verificado com um | INVÁLIDA |

**Modos de falha da validação** (`evidencias/06-validacao/modos-de-falha/`):

| Cenário | DNs | Assinatura | Ext. PQC | Assin. alt. | Global |
|---|---|---|---|---|---|
| Caminho feliz | ✓ | ✓ | ✓ | ✓ | **válido** |
| Emissor errado | ✗ | ✗ | ✓ | ✗ | inválido |
| Chave pública de emissor errada | ✓ | ✗ | ✓ | ✗ | inválido |
| Sem chave de emissor (folha de CA) | ✓ | ✗ | ✓ | ✗ | inválido |
| Certificado sem extensões Catalyst | ✓ | ✓ | ✗ | ✗ | inválido |

A terceira linha é a mais relevante: quando nenhuma chave de emissor é fornecida e o
certificado não é autoassinado, a assinatura é reportada como **inválida**, não presumida
válida.

**Cadeia com âncora substituída.** Duas raízes com Distinguished Name idêntico: a cadeia com a
raiz impostora falha nas duas dimensões, mostrando que o vínculo é criptográfico e não nominal.

---

## 6. Divergências entre a evidência e o texto do TCC

Nenhuma destas é defeito de código; são correções a fazer no documento.

**6.1 A linha do ML-DSA-65 na `tab:tamanhos` contém os valores do ML-DSA-44.**

| Grandeza | TCC diz | Evidência mede |
|---|---:|---:|
| Chave pública ML-DSA-65 | 1.312 | **1.952** (crua) / 1.974 (SPKI) |
| Assinatura ML-DSA-65 | 2.420 | **3.309** |

Os valores do TCC (1312 / 2560 / 2420) são exatamente os do ML-DSA-44.

**6.2 Consequência: a razão de tamanho está subestimada.** O texto diz que a assinatura
pós-quântica é "cerca de 35 vezes" a clássica (2420/70). Com o valor correto, é **47×**
(3309/70).

**6.3 A faixa de tamanho do certificado Catalyst está subestimada.** O texto indica "3,5 a
4,5 kB" para ECDSA-P384 + ML-DSA-65. O medido é **5.868 bytes (~5,9 kB)**.

**6.4 A base de medição da `tab:tamanhos` é inconsistente.** Os valores clássicos (91 para
P-256, 294 para RSA-2048) são tamanhos **SPKI em DER** — e conferem exatamente com a
evidência. Já os de ML-DSA são tamanhos de **chave crua**. Misturar as duas bases numa mesma
tabela induz o leitor a comparações erradas. Recomenda-se declarar a base explicitamente, ou
apresentar as duas colunas, como faz a tabela 3.1 deste relatório.

**6.5 A `lst:saida-certificado` mistura dois níveis.** A listagem mostra chave alternativa de
1.978 B (ML-DSA-65) com assinatura alternativa de 4.636 B (ML-DSA-87). Isso é *tecnicamente
coerente* — a extensão 72 traz a chave do sujeito e a 74 a assinatura do emissor —, mas o texto
ao redor atribui ambas ao mesmo algoritmo. Vale explicitar de quem é cada uma.

**6.6 A listagem cita `SHA256WITHECDSA` sobre chave P-384.** Era o sintoma do defeito de
seleção de digest, hoje corrigido. A evidência atual mostra `ecdsa-with-SHA384`. A listagem
precisa ser regerada antes da defesa.

---

## 7. Limitações da evidência

Registradas para que o alcance do relatório não seja superestimado.

1. **Tamanhos de chave privada não são corroboráveis.** A biblioteca deliberadamente não
   exporta material privado, e a campanha respeita isso. Os valores de chave privada da
   `tab:tamanhos` do TCC (138, 1.704, 2.560) **não foram verificados** por esta campanha e
   permanecem em aberto. O 1.704 para RSA-2048 continua parecendo alto: um PKCS#8 DER de
   RSA-2048 costuma ficar em torno de 1.218 bytes.

2. **Não há caracterização de desempenho.** Os tempos registrados são de execução única, sem
   aquecimento de JVM, e servem apenas para ordem de grandeza. A infraestrutura JMH existe no
   repositório (`-Pbenchmark`) mas não foi exercitada aqui.

3. **A evidência não é determinística.** Chaves e assinaturas são aleatórias e a validade parte
   de `Instant.now()`, de modo que regerar a campanha muda todos os bytes. O manifesto registra
   data, commit e hashes, que é o que torna uma execução específica rastreável.

4. **Um único ambiente.** Toda a evidência vem de uma combinação Java 21.0.11 / BC 1.84 /
   OpenSSL 3.0.13 / Linux. Nada aqui sustenta afirmações sobre outros provedores ou versões.

5. **O verificador legado é representado por duas implementações.** `openssl verify` e o
   `CertPathValidator` do JDK. Navegadores e bibliotecas TLS não foram testados.

---

## 8. Achado incidental durante a análise

A matriz de disponibilidade de algoritmos (área 8) listava `SHA256withRSA` em duas linhas
consecutivas sem distinguir a variante, porque RSA-2048 e RSA-3072 compartilham o mesmo nome
JCA de assinatura. Parecia uma duplicata na evidência. Foi corrigido com o acréscimo de uma
coluna de variante, e a campanha regerada.

Registro o achado porque ele ilustra o valor de analisar a evidência em vez de apenas
produzi-la: o defeito estava no relatório, não no módulo, e só apareceu na leitura atenta da
saída.

---

## 9. Como reproduzir e conferir

```sh
# regerar toda a evidência
mvn test -Pvalidacao

# conferir integridade
cd evidencias && sha256sum -c SHA256SUMS

# conferir a cadeia com ferramenta externa
cd evidencias/03-autoridade-certificadora/cadeia-tres-niveis
openssl verify -CAfile raiz.pem -untrusted subca.pem folha.pem

# inspecionar um certificado híbrido
openssl x509 -in evidencias/02-emissao-certificados/nivel-192/certificado.pem -noout -text
```

A campanha fica fora do build padrão: `mvn test` e `mvn verify` executam os 270 testes
unitários sem tocar em `evidencias/`.
