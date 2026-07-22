AES Encryption and Decryption (AES + Base64)

<details> <summary><b>🇧🇷 Clique aqui para ler em Português</b></summary> <br>

Sistema de criptografia e descriptografia desenvolvido em Java utilizando o algoritmo AES (Advanced Encryption Standard) com codificação Base64, criado para fins de estudo em cibersegurança e proteção de dados.

Funcionalidades
Criptografia Simétrica: Utiliza o algoritmo AES para proteger informações.
Codificação Base64: Converte os dados criptografados para um formato seguro e legível para armazenamento ou transmissão.
Descriptografia: Recupera o texto original utilizando a mesma chave criptográfica.
Sem Dependências: Desenvolvido inteiramente em Java nativo, utilizando apenas as bibliotecas padrão da Java Cryptography Architecture (JCA).
Tecnologias Utilizadas
Java
Java Cryptography Architecture (JCA)
AES (Advanced Encryption Standard)
Base64
Estrutura do Projeto
Projeto/
│── CriptographSystem.java
│── DescryptorSystem.java
│── relatorio_seguranca.txt
└── README.md
Como Compilar e Executar

Abra o terminal no diretório do projeto e execute:

javac CriptographSystem.java
javac DescryptorSystem.java

java CriptographSystem

ou

java DescryptorSystem
Funcionamento
O usuário informa um texto.
O sistema realiza a criptografia utilizando AES.
O resultado é convertido para Base64.
O texto pode ser descriptografado utilizando a mesma chave AES.
Aviso

Este projeto possui finalidade educacional. Em aplicações reais, recomenda-se utilizar modos de operação seguros, como AES-GCM ou AES-CBC com vetor de inicialização (IV), além de gerenciamento adequado das chaves criptográficas.

</details>

<details open> <summary><b>🇺🇸 Click here to read in English</b></summary> <br>

An encryption and decryption system developed in Java using the AES (Advanced Encryption Standard) algorithm with Base64 encoding for cybersecurity and data protection studies.

Features
Symmetric Encryption: Uses the AES algorithm to secure information.
Base64 Encoding: Converts encrypted data into a safe and readable format for storage and transmission.
Decryption: Restores the original plaintext using the same cryptographic key.
Zero Dependencies: Built entirely with native Java using only the Java Cryptography Architecture (JCA).
Technologies Used
Java
Java Cryptography Architecture (JCA)
AES (Advanced Encryption Standard)
Base64
Project Structure
Project/
│── CriptographSystem.java
│── DescryptorSystem.java
│── relatorio_seguranca.txt
└── README.md
How to Compile and Run

Open the terminal in the project directory and execute:

javac CriptographSystem.java
javac DescryptorSystem.java

java CriptographSystem

or

java DescryptorSystem
How It Works
The user enters a text.
The system encrypts it using AES.
The encrypted data is encoded in Base64.
The original text is recovered using the same AES key.
Disclaimer

This project is intended for educational purposes. In production environments, it is recommended to use secure operation modes such as AES-GCM or AES-CBC with an Initialization Vector (IV), along with proper cryptographic key management.

</details>