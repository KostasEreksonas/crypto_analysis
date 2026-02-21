# crypto_analysis
A (vibe-)coded Rust tool to scan Linux binaries and libraries for cryptographic signatures

Table of Contents
=================
* [Usage](#usage)
* [Results](#results)
* [Scanned Algorithms](#scanned-algorithms)

# Usage

```
cd crypto_analysis

cargo run -- -j "$(nproc)" -o results.txt
```

# Results

```
=== Scanning 20588 files from 16 directories ===

Directories being scanned:
  - /home/kostas/.cargo/bin
  - /home/kostas/.local/bin
  - /lib
  - /lib64
  - /opt/cuda/bin
  - /opt/cuda/integration/nsight-compute
  - /opt/cuda/integration/nsight-systems
  - /usr/bin
  - /usr/bin/core_perl
  - /usr/bin/site_perl
  - /usr/bin/vendor_perl
  - /usr/lib
  - /usr/lib/packettracer
  - /usr/lib64
  - /usr/local/bin
  - /usr/local/lib

#     	File                                              	Primitives
=     	====                                              	==========
1     	/usr/bin/kdestroy                                 	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_SABER_q CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
2     	/usr/lib64/libkeyutils.so                         	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
3     	/lib64/libevent_openssl-2.1.so.7.0.1              	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
4     	/lib/libgailutil-3.so.0.0.0                       	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
5     	/usr/lib64/libQt6QuickWidgets.so                  	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_NTRU_n509 PQC_NTRU_n821 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p384 ZLIB_lengthextrabits
6     	/usr/lib/libnghttp3.so.9.6.1                      	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_NTRU_n509 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p256 EC_p384 ZLIB_lengthextrabits
7     	/lib/libgexiv2.so.2.14.6                          	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_q PQC_Kyber_n256 PQC_Falcon_q_LE PQC_Falcon_q_BE PQC_NTRU_n509 PQC_NTRU_n677 PQC_NTRU_n821 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
8     	/usr/lib/libnewt.so.0.52.25                       	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_NTRU_n677 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p384 ZLIB_lengthextrabits
9     	/usr/lib/libduktape.so.207.20700                  	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_q PQC_Kyber_n256 PQC_Falcon_q_LE PQC_Falcon_q_BE PQC_NTRU_n677 PQC_NTRU_n821 PQC_SABER_q PQC_HQC IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p384 ZLIB_lengthextrabits
10    	/usr/lib64/libtracefs.so.1                        	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p384 ZLIB_lengthextrabits
11    	/usr/lib/libminizip.so.1.0.0                      	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_NTRU_n677 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
12    	/usr/lib/libdrm_amdgpu.so.1.131.0                 	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_NTRU_n509 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
13    	/lib64/libpango-1.0.so.0                          	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_q PQC_Kyber_n256 PQC_Falcon_q_LE PQC_Falcon_q_BE PQC_NTRU_n509 PQC_NTRU_n677 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p384 ZLIB_lengthextrabits
14    	/lib64/libffcall.so.0.1.1                         	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_BE PQC_NTRU_n509 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
15    	/usr/lib/libgd.so                                 	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_LE PQC_Falcon_q_BE PQC_NTRU_n509 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p384 ZLIB_lengthextrabits
16    	/usr/lib/libevent_pthreads-2.1.so.7               	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 ZLIB_lengthextrabits
17    	/usr/lib/libQt6LabsPlatform.so                    	RSA_e65537_BE32 RSA_e65537_LE32 RSA_e65537_BE64 RSA_e65537_LE64 RSA_e3_BE32 RSA_e3_LE32 RSA_e17_BE32 RSA_e257_BE32 RSA_e257_LE32 PQC_Kyber_n256 PQC_Falcon_q_LE PQC_Falcon_q_BE PQC_NTRU_n509 PQC_NTRU_n821 PQC_SABER_q IKE_prime CRC32_lzma_1 CRC32_m_tab_be CRC32_m_tab_le CRC32_ms_0 EC_p192 EC_p224 EC_p384 ZLIB_lengthextrabits
...
```

# Scanned Algorithms

Classical Symmetric Encryption

    AES (Advanced Encryption Standard)

    Blowfish

    ChaCha20

    DES (Data Encryption Standard)

    3DES / Triple DES

    ARIA

    DFC

    KASUMI

    NewDES

    RC5

    RC6

    Salsa20

    SM4

    TEA (Tiny Encryption Algorithm)

Hash Functions

    MD5

    RIPEMD

    SHA-1

    SHA-224

    SHA-256

    SHA-512

    SHA-3

    SipHash

    Whirlpool

    BLAKE-224

    BLAKE-256

    BLAKE-384

    BLAKE-512

    SM3

Asymmetric (Public-Key) Cryptography

    RSA (various public exponents: 3, 17, 257, 65537)

Elliptic Curve Cryptography

    Curve25519

    NIST P-192

    NIST P-224

    NIST P-256

    NIST P-384

    NIST P-521

Post-Quantum Cryptography (PQC)
Lattice-Based

    CRYSTALS-Kyber (ML-KEM, FIPS 203)

    CRYSTALS-Dilithium (ML-DSA, FIPS 204)

    Falcon (FN-DSA)

    NTRU

    SABER

Hash-Based

    SPHINCS+ (SLH-DSA, FIPS 205)

    XMSS (eXtended Merkle Signature Scheme)

    LMS (Leighton-Micali Signature)

    HSS (Hierarchical Signature System)

Code-Based

    Classic McEliece

    BIKE

    HQC (Hamming Quasi-Cyclic)

Multivariate

    Rainbow

Isogeny-Based

    CSIDH

    SQIsign

Key Exchange / Agreement

    IKE (Internet Key Exchange)

Checksums / Error Detection

    CRC32 (multiple variants)

    ZLIB compression algorithms

Pseudorandom Number Generators

    MT19937 (Mersenne Twister)
