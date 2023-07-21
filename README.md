# PIL
Copyright @ sunshuang618@gmail.com
This is a Privacy Identity Lottery model which mainly utilizing the underlying logic of the Grabled Circuits
Includes three entitites: (1) Server. Responsible for generating the pesudo-random function, garbled values and a proof message 'proofs'.
(2) Client. There could be multiple clients, but the algorithm operates on a one-to-one basis. Responsible for calculating the garbled values and the validation message 'PROOF'.
(3) Verifier. Could be any one who interested in this lottery process. Responsible for decrypting and comparing each variable value generated by the server with those generated by the client.
I implemented the entire protocol flow in a single program process.
Plain C, Visual Studio, OpenSSL
Hash: SHA-256, based on OpenSSL. Asymmetric encryption: RSA-256, based on OpenSSL. Symmetric encryption: SM4-128, implemented by myself
Hash operations: 2.              Asymmetric operations: 8.                         Symmetric operations: 16.
Performance: approximately 11.62 milliseconds at a time.
