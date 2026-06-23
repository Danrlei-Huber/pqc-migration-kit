# TODO — pqc-migration-kit

Lista de pendências conhecidas (bugs e melhorias). Itens marcados `[ ]` estão abertos.

---

## Bugs

### [ ] `extractCertificateInfo`: falha ao montar `PQCExtensionsStructure`

- **Sintoma (log):**
  ```
  WARNING: Failed to build PQC extensions structure:
           unknown object in getInstance: org.bouncycastle.asn1.DEROctetString
  ```
- **Onde:** `HybridCertificateValidator.buildPQCExtensionsFromExtMap(...)`
  (`src/main/java/com/pqc/hybrid/core/certificate/HybridCertificateValidator.java:398-416`),
  chamado por `extractCertificateInfo(...)` (linha ~389) dentro de um `try/catch` que
  só loga o warning e segue.
- **Causa provável:** uma das conversões a partir de `Extension.getParsedValue()` recebe um
  `DEROctetString` em vez do tipo ASN.1 esperado — candidatos:
  - linha 408: `AlgorithmIdentifier.getInstance(altAlg.getParsedValue())`
  - linha 412: `ASN1OctetString.getInstance(altKey.getParsedValue()).getOctets()`
    seguido de `SubjectPublicKeyInfo.getInstance(spkiBytes)` (linha 413)
  - linha 410: `((DERBitString) altSig.getParsedValue()).getOctets()`
  Provável duplo embrulho: `getParsedValue()` já devolve o conteúdo da OCTET STRING da
  extensão, e há um `getInstance`/cast a mais. Comparar com como
  `extractPQCAlgorithmOID` / `extractPQCSignature` / `extractPQCPublicKey`
  (mesmas extensões) fazem o parsing a partir de `getExtensionValue(oid)` — esses
  funcionam — e alinhar `buildPQCExtensionsFromExtMap` ao mesmo caminho.
- **Impacto:** `getCertificateInfo(cert, keyPair)` ainda funciona e popula os campos PQC
  (alg, OID, tamanhos de chave/assinatura); apenas o objeto `PQCExtensionsStructure`
  fica `null` (`info.getPQCExtensions()` retorna `null`, `hasPQCExtensions()` = false).
  Não quebra o fluxo de produção nem a validação de cadeia.
- **Repro:** `./run-examples.sh flow` (passo 5, extração do `HybridCertificateInfo`) ou
  `mvn test` — o warning aparece em `extractCertificateInfo`.
- **Sugestão de correção:** depurar qual das 3 extensões dispara o erro
  (logar `getParsedValue().getClass()` de cada uma), remover o nível extra de
  `getInstance`/desembrulho, e adicionar um teste cobrindo
  `getCertificateInfo(...).getPQCExtensions() != null` para um cert Catalyst.

---

## Melhorias / Inconsistências

### [ ] Logs `INFO` poluem a saída dos exemplos antigos

- **Sintoma:** ao rodar `./run-examples.sh sign` (e `cert`, `algorithms`, `generation`,
  `helper`), os logs `java.util.logging` `INFO` aparecem no meio do fluxo, ex.:
  ```
  INFO: BouncyCastle provider initialized
  INFO: All required PQC algorithms are available
  INFO: Signed data with hybrid signature: ECDSA + ML-DSA-87
  ```
- **Inconsistência:** o `LibraryFlowWalkthroughExample` (`flow`) já silencia esses logs por
  padrão e expõe a flag `-v`/`--verbose` para reativá-los; os demais exemplos não.
- **Impacto:** apenas estético, mas atrapalha a leitura/demonstração (defesa do TCC).
- **Sugestão:** aplicar o mesmo padrão (`LogManager.getLogManager().reset()` por padrão +
  flag `-v`) aos exemplos `SignAndVerifyExample`, `GenerateCertificateExample`,
  `AlgorithmExplorerExample`, `HybridCertificateGenerationExample` e `HybridCertificateHelper`;
  ou centralizar o ajuste de logging no `run-examples.sh`.
