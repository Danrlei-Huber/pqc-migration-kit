| Cenário | JDK PKIX | openssl verify | core native | core strict | core hybrid-issuer | core hybrid-issuer {65,87} | core classical-only |
|---|---|---|---|---|---|---|---|
| Íntegro | aceita | aceita | VALID | VALID | VALID | VALID | VALID |
| Assinadores misturados (clássica da AC + ML-DSA do atacante) | aceita | aceita | INVALID | INVALID | INVALID | INVALID | VALID |
| Stripping (só clássico, chave da AC) | aceita | aceita | VALID | INVALID | INVALID | INVALID | VALID |
| Algoritmo alternativo fora da lista (ML-DSA-44) | aceita | aceita | VALID | VALID | VALID | INVALID | VALID |
| Assinatura clássica inválida (clássica do atacante + ML-DSA da AC) | rejeita | rejeita | INVALID | INVALID | INVALID | INVALID | INVALID |
| Emissor sem chave alternativa (AC só clássica) | aceita | aceita | INVALID | INVALID | INVALID | INVALID | VALID |
| Cadeia puramente clássica (controle) | — | — | VALID | INVALID | VALID | VALID | VALID |
