# Exemplo de criptografia não segura para senha

## Descrição

Neste exemplo, é usado o algoritmo AES para criptografar e descriptografar a senha. No entanto, é importante destacar que o segundo exemplo não é considerado seguro para armazenamento de senhas, pois envolve criptografia bidirecional, o que implica a possibilidade de recuperação da senha original se a chave for comprometida.

Em cenários de armazenamento de senhas, a prática recomendada é o uso de funções de hash unidirecionais, como bcrypt ou Argon2, que dificultam a recuperação da senha original, mesmo se a chave for comprometida.

Lembre-se de escolher as técnicas de criptografia adequadas com base nos requisitos de segurança e nas melhores práticas estabelecidas.

