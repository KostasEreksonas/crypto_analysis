use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::HashSet;
use regex::bytes::Regex;

struct CryptoPattern {
    name: &'static str,
    pattern: Vec<u8>,
}

impl CryptoPattern {
    fn new(name: &'static str, pattern: Vec<u8>) -> Self {
        Self { name, pattern }
    }

    fn matches(&self, content: &[u8]) -> bool {
        content.windows(self.pattern.len())
            .any(|window| window == self.pattern.as_slice())
    }
}

// Thread-safe dual writer
struct DualWriter {
    file: Option<Arc<Mutex<fs::File>>>,
}

impl DualWriter {
    fn new(output_file: Option<&str>) -> std::io::Result<Self> {
        let file = if let Some(path) = output_file {
            Some(Arc::new(Mutex::new(fs::File::create(path)?)))
        } else {
            None
        };
        Ok(Self { file })
    }

    fn writeln(&self, text: &str) {
        println!("{}", text);
        
        if let Some(ref f) = self.file {
            if let Ok(mut file) = f.lock() {
                writeln!(file, "{}", text).unwrap_or_else(|e| {
                    eprintln!("Warning: Failed to write to file: {}", e);
                });
            }
        }
    }

    fn write(&self, text: &str) {
        print!("{}", text);
        
        if let Some(ref f) = self.file {
            if let Ok(mut file) = f.lock() {
                write!(file, "{}", text).unwrap_or_else(|e| {
                    eprintln!("Warning: Failed to write to file: {}", e);
                });
            }
        }
    }

    fn clone_file_handle(&self) -> Option<Arc<Mutex<fs::File>>> {
        self.file.clone()
    }
}

// Thread-safe result writer for scanning results
struct ResultWriter {
    file: Option<Arc<Mutex<fs::File>>>,
}

impl ResultWriter {
    fn new(file_handle: Option<Arc<Mutex<fs::File>>>) -> Self {
        Self { file: file_handle }
    }

    fn write_result(&self, result: &str) {
        print!("{}", result);
        std::io::stdout().flush().ok();
        
        if let Some(ref f) = self.file {
            if let Ok(mut file) = f.lock() {
                write!(file, "{}", result).ok();
            }
        }
    }
}

fn get_crypto_patterns() -> Vec<CryptoPattern> {
    vec![
        // Classical crypto patterns
        CryptoPattern::new("AES", vec![0x63, 0x7c, 0x77, 0x7b]),
        CryptoPattern::new("BLOWFISH", vec![0xd1, 0x31, 0x0b, 0xa6]),
        CryptoPattern::new("ChaCha20", b"expand 32-byte k".to_vec()),
        CryptoPattern::new("curve25519", vec![
            0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9,
            0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
            0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
            0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21
        ]),
        CryptoPattern::new("DES", vec![0x80, 0x10, 0x80, 0x20]),
        CryptoPattern::new("MD5", vec![0xd7, 0x6a, 0xa4, 0x78]),
        CryptoPattern::new("RIPEMD", vec![0xE9, 0x76, 0x6d, 0x7a]),
        CryptoPattern::new("SHA1", vec![0x5a, 0x82, 0x79, 0x99]),
        CryptoPattern::new("SHA256", vec![0xd8, 0x9e, 0x05, 0xc1]),
        CryptoPattern::new("SHA512", vec![0xa2, 0x4d, 0x54, 0x19, 0xc8, 0x37, 0x3d, 0x8c]),
        CryptoPattern::new("SHA3", vec![0x89, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]),
        CryptoPattern::new("SIPHASH", b"uespemos".to_vec()),
        CryptoPattern::new("WHIRLPOOL", vec![0x18, 0x18, 0x60, 0x18, 0xc0, 0x78, 0x30, 0xd8]),

        // RSA patterns
        CryptoPattern::new("RSA_e65537_BE32", vec![0x00, 0x01, 0x00, 0x01]),
        CryptoPattern::new("RSA_e65537_LE32", vec![0x01, 0x00, 0x01, 0x00]),
        CryptoPattern::new("RSA_e65537_BE64", vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]),
        CryptoPattern::new("RSA_e65537_LE64", vec![0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
        CryptoPattern::new("RSA_e3_BE32", vec![0x00, 0x00, 0x00, 0x03]),
        CryptoPattern::new("RSA_e3_LE32", vec![0x03, 0x00, 0x00, 0x00]),
        CryptoPattern::new("RSA_e17_BE32", vec![0x00, 0x00, 0x00, 0x11]),
        CryptoPattern::new("RSA_e257_BE32", vec![0x00, 0x00, 0x01, 0x01]),
        CryptoPattern::new("RSA_e257_LE32", vec![0x01, 0x01, 0x00, 0x00]),

        // Post-Quantum Cryptography (PQC) - NIST Standardized Algorithms
        
        // CRYSTALS-Kyber (ML-KEM - FIPS 203) - Lattice-based KEM
        // Kyber uses polynomial ring Zq[X]/(X^256+1), q = 3329
        CryptoPattern::new("PQC_Kyber_q", vec![0x01, 0x0D]), // q = 3329 (0x0D01) little-endian
        CryptoPattern::new("PQC_Kyber_n256", vec![0x00, 0x01, 0x00, 0x00]), // n = 256
        
        // CRYSTALS-Dilithium (ML-DSA - FIPS 204) - Lattice-based signature
        // Dilithium also uses q = 8380417 (0x7FE001)
        CryptoPattern::new("PQC_Dilithium_q_LE", vec![0x01, 0xE0, 0x7F, 0x00]), // q = 8380417 little-endian
        CryptoPattern::new("PQC_Dilithium_q_BE", vec![0x00, 0x7F, 0xE0, 0x01]), // q = 8380417 big-endian
        
        // SPHINCS+ (SLH-DSA - FIPS 205) - Hash-based signature
        // SPHINCS+ uses SHAKE256 as one of its hash functions
        CryptoPattern::new("PQC_SPHINCS_SHAKE", b"SPHINCS+".to_vec()),
        
        // Falcon (FN-DSA) - Lattice-based signature (NIST selected)
        // Falcon uses NTRU lattices, q = 12289 (0x3001)
        CryptoPattern::new("PQC_Falcon_q_LE", vec![0x01, 0x30]), // q = 12289 little-endian
        CryptoPattern::new("PQC_Falcon_q_BE", vec![0x30, 0x01]), // q = 12289 big-endian
        
        // NTRU - Lattice-based encryption (Round 3 finalist)
        // NTRU uses N = 509, 677, 821 for different security levels
        CryptoPattern::new("PQC_NTRU_n509", vec![0xFD, 0x01, 0x00, 0x00]), // N = 509 little-endian
        CryptoPattern::new("PQC_NTRU_n677", vec![0xA5, 0x02, 0x00, 0x00]), // N = 677 little-endian
        CryptoPattern::new("PQC_NTRU_n821", vec![0x35, 0x03, 0x00, 0x00]), // N = 821 little-endian
        
        // SABER - Lattice-based KEM (Round 3 finalist)
        // Saber uses q = 2^13 = 8192
        CryptoPattern::new("PQC_SABER_q", vec![0x00, 0x20, 0x00, 0x00]), // q = 8192 (2^13) little-endian
        
        // Classic McEliece - Code-based encryption (NIST selected)
        CryptoPattern::new("PQC_McEliece", b"mceliece".to_vec()),
        
        // BIKE - Code-based KEM
        CryptoPattern::new("PQC_BIKE", b"BIKE".to_vec()),
        
        // HQC (Hamming Quasi-Cyclic) - Code-based KEM
        CryptoPattern::new("PQC_HQC", b"HQC".to_vec()),
        
        // Rainbow - Multivariate signature (withdrawn due to attack)
        CryptoPattern::new("PQC_Rainbow", b"Rainbow".to_vec()),
        
        // XMSS (eXtended Merkle Signature Scheme) - Hash-based signature
        CryptoPattern::new("PQC_XMSS", b"XMSS".to_vec()),
        
        // LMS/HSS (Leighton-Micali Signature / Hierarchical Signature System)
        CryptoPattern::new("PQC_LMS", b"LMS".to_vec()),
        CryptoPattern::new("PQC_HSS", b"HSS".to_vec()),
        
        // CSIDH - Isogeny-based key exchange
        CryptoPattern::new("PQC_CSIDH", b"CSIDH".to_vec()),
        
        // SQIsign - Isogeny-based signature
        CryptoPattern::new("PQC_SQIsign", b"SQIsign".to_vec()),

        // Patterns from cryptoscan repository
        CryptoPattern::new("IKE_prime", vec![0xFF, 0xFF, 0xFF, 0xFF]),
        CryptoPattern::new("AES_sbox", vec![0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
        CryptoPattern::new("AES_inv_sbox", vec![0x52, 0x09, 0x6a, 0xd5]),
        CryptoPattern::new("AES_td0", vec![0x50, 0xa7, 0xf4, 0x51]),
        CryptoPattern::new("AES_td1", vec![0x50, 0x50, 0xa7, 0xf4]),
        CryptoPattern::new("AES_td2", vec![0xf4, 0x51, 0x50, 0x50]),
        CryptoPattern::new("AES_td3", vec![0x51, 0xf4, 0x51, 0x50]),
        CryptoPattern::new("AES_td4", vec![0x52, 0x52, 0x09, 0x09]),
        CryptoPattern::new("AES_te0", vec![0xc6, 0x63, 0x63, 0xa5]),
        CryptoPattern::new("AES_te1", vec![0xa5, 0xc6, 0x63, 0x63]),
        CryptoPattern::new("AES_te2", vec![0x63, 0xa5, 0xc6, 0x63]),
        CryptoPattern::new("AES_te3", vec![0x63, 0x63, 0xa5, 0xc6]),
        CryptoPattern::new("AES_te4", vec![0x63, 0x63, 0x7c, 0x7c]),
        CryptoPattern::new("ARIA_sbox2", vec![0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc]),
        CryptoPattern::new("ARIA_sbox4", vec![0xe2, 0x4e, 0x54, 0xfc, 0x00, 0x00, 0x00, 0x00]),
        CryptoPattern::new("BLAKE_224", vec![0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07]),
        CryptoPattern::new("BLAKE_256", vec![0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85]),
        CryptoPattern::new("BLAKE_384", vec![0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8]),
        CryptoPattern::new("BLAKE_512", vec![0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08]),
        CryptoPattern::new("BLOWFISH_p_array", vec![0x24, 0x3f, 0x6a, 0x88]),
        CryptoPattern::new("BLOWFISH_sbox", vec![0xd1, 0x31, 0x0b, 0xa6, 0x98, 0xdf, 0xb5, 0xac]),
        CryptoPattern::new("CRC32_lzma_0", vec![0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96]),
        CryptoPattern::new("CRC32_lzma_1", vec![0x00, 0x00, 0x00, 0x00]),
        CryptoPattern::new("CRC32_lzma_2", vec![0x00, 0x00, 0x00, 0x00, 0xb8, 0xbc, 0x65, 0x65]),
        CryptoPattern::new("CRC32_lzma_3", vec![0x00, 0x00, 0x00, 0x00, 0xee, 0x0e, 0x61, 0x2c]),
        CryptoPattern::new("CRC32_lzma_4", vec![0x00, 0x00, 0x00, 0x00, 0x76, 0xdc, 0x41, 0x90]),
        CryptoPattern::new("CRC32_lzma_5", vec![0x00, 0x00, 0x00, 0x00, 0x01, 0xdb, 0x71, 0x06]),
        CryptoPattern::new("CRC32_lzma_6", vec![0x00, 0x00, 0x00, 0x00, 0x69, 0x6c, 0x2b, 0xd6]),
        CryptoPattern::new("CRC32_lzma_7", vec![0x00, 0x00, 0x00, 0x00, 0x1e, 0x6d, 0xdf, 0x40]),
        CryptoPattern::new("CRC32_m_tab_be", vec![0x00, 0x00, 0x00, 0x00]),
        CryptoPattern::new("CRC32_m_tab_le", vec![0x00, 0x00, 0x00, 0x00]),
        CryptoPattern::new("CRC32_ms_0", vec![0x00, 0x00, 0x00, 0x00]),
        CryptoPattern::new("CRC32_ms_1", vec![0x00, 0x00, 0x00, 0x00, 0xb8, 0xbc, 0x65, 0x65]),
        CryptoPattern::new("CRC32_ms_2", vec![0x00, 0x00, 0x00, 0x00, 0xee, 0x0e, 0x61, 0x2c]),
        CryptoPattern::new("CRC32_ms_3", vec![0x00, 0x00, 0x00, 0x00, 0x76, 0xdc, 0x41, 0x90]),
        CryptoPattern::new("CRC32_ms_4", vec![0x00, 0x00, 0x00, 0x00, 0x01, 0xdb, 0x71, 0x06]),
        CryptoPattern::new("CRC32_ms_5", vec![0x00, 0x00, 0x00, 0x00, 0x69, 0x6c, 0x2b, 0xd6]),
        CryptoPattern::new("CRC32_ms_6", vec![0x00, 0x00, 0x00, 0x00, 0x1e, 0x6d, 0xdf, 0x40]),
        CryptoPattern::new("DES_p32i", vec![0x10, 0x07, 0x14, 0x15]),
        CryptoPattern::new("DES_pc1_left", vec![0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01]),
        CryptoPattern::new("DES_pc1_right", vec![0x3f, 0x37, 0x2f, 0x27, 0x1f, 0x17, 0x0f, 0x07]),
        CryptoPattern::new("DES_pc2", vec![0x0e, 0x11, 0x0b, 0x18]),
        CryptoPattern::new("DES_sbox1", vec![0x0e, 0x04, 0x0d, 0x01]),
        CryptoPattern::new("DES_sbox2", vec![0x0f, 0x01, 0x08, 0x0e]),
        CryptoPattern::new("DES_sbox3", vec![0x0a, 0x00, 0x09, 0x0e]),
        CryptoPattern::new("DES_sbox4", vec![0x07, 0x0d, 0x0a, 0x01]),
        CryptoPattern::new("DES_sbox5", vec![0x02, 0x0c, 0x04, 0x01]),
        CryptoPattern::new("DES_sbox6", vec![0x0c, 0x01, 0x0a, 0x0f]),
        CryptoPattern::new("DES_sbox7", vec![0x04, 0x0b, 0x02, 0x0e]),
        CryptoPattern::new("DES_sbox8", vec![0x0d, 0x02, 0x08, 0x04]),
        CryptoPattern::new("DFC_sbox", vec![0xb7, 0xe1, 0x51, 0x62, 0x8a, 0xed, 0x2a, 0x6a]),
        CryptoPattern::new("EC_curve25519", vec![0x1A, 0xD5, 0x25, 0x8F]),
        CryptoPattern::new("EC_p192", vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        CryptoPattern::new("EC_p224", vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        CryptoPattern::new("EC_p256", vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01]),
        CryptoPattern::new("EC_p384", vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        CryptoPattern::new("EC_p521", vec![0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        CryptoPattern::new("KASUMI_mod", vec![0x01, 0x69, 0x00, 0x01, 0xB3, 0x00, 0x01, 0x65]),
        CryptoPattern::new("KASUMI_sbox_s7", vec![0x36, 0x4C, 0x2A, 0x6D, 0x4B, 0x53, 0x1D, 0x60]),
        CryptoPattern::new("KASUMI_sbox_s9", vec![0x00A7, 0x00BC, 0x00D3, 0x0046, 0x009F, 0x0067, 0x0030, 0x00E9]),
        CryptoPattern::new("MD5_initstate", vec![0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89]),
        CryptoPattern::new("MD5_t", vec![0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56]),
        CryptoPattern::new("MT19937_1", vec![0x6c, 0x07, 0x82, 0x79]),
        CryptoPattern::new("MT19937_2", vec![0x9d, 0x2c, 0x58, 0x80]),
        CryptoPattern::new("MT19937_3", vec![0xee, 0xa1, 0x28, 0x14]),
        CryptoPattern::new("MT19937_4", vec![0x0e, 0xab, 0x70, 0xd0]),
        CryptoPattern::new("MT19937_matrix", vec![0x00, 0x00, 0x00, 0x00, 0x9d, 0x2c, 0x58, 0x80]),
        CryptoPattern::new("NewDES_sbox", vec![0x20, 0x44, 0x65, 0x6d, 0x6f, 0x6e, 0x73, 0x74]),
        CryptoPattern::new("RC5_RC6", vec![0xb7, 0xe1, 0x51, 0x62, 0x8a, 0xed, 0x2a, 0x6a]),
        CryptoPattern::new("Salsa20_sigma", b"expand 32-byte k".to_vec()),
        CryptoPattern::new("Salsa20_tau", b"expand 16-byte k".to_vec()),
        CryptoPattern::new("SHA1_h", vec![0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89]),
        CryptoPattern::new("SHA224_h", vec![0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07]),
        CryptoPattern::new("SHA256_h", vec![0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85]),
        CryptoPattern::new("SHA256_k", vec![0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91]),
        CryptoPattern::new("SHA512_k", vec![0x42, 0x8a, 0x2f, 0x98, 0xd7, 0x28, 0xae, 0x22]),
        CryptoPattern::new("SM3_init", vec![0x73, 0x80, 0x16, 0x6f, 0x49, 0x14, 0xb2, 0xb9]),
        CryptoPattern::new("SM4_ck", vec![0x00, 0x07, 0x0e, 0x15, 0x1c, 0x23, 0x2a, 0x31]),
        CryptoPattern::new("SM4_fk", vec![0xa3, 0xb1, 0xba, 0xc6, 0x56, 0xaa, 0x3e, 0x50]),
        CryptoPattern::new("SM4_sbox", vec![0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7]),
        CryptoPattern::new("TEA_delta", vec![0x9e, 0x37, 0x79, 0xb9]),
        CryptoPattern::new("ZLIB_distanceextrabits", vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02]),
        CryptoPattern::new("ZLIB_distancestarts", vec![0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]),
        CryptoPattern::new("ZLIB_lengthextrabits", vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        CryptoPattern::new("ZLIB_lengthstarts", vec![0x00, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]),
    ]
}

fn scan_file<'a>(path: &PathBuf, patterns: &'a [CryptoPattern]) -> Option<Vec<&'a str>> {
    let mut file = fs::File::open(path).ok()?;
    let mut content = Vec::new();
    file.read_to_end(&mut content).ok()?;
    
    let mut found = Vec::new();
    for pattern in patterns {
        if pattern.matches(&content) {
            found.push(pattern.name);
        }
    }
    
    if found.is_empty() {
        None
    } else {
        Some(found)
    }
}

fn scan_directories(dirs: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    
    for dir_path in dirs {
        let dir = PathBuf::from(dir_path);
        if !dir.exists() {
            eprintln!("Warning: Directory {} does not exist, skipping", dir_path);
            continue;
        }
        
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    files.push(path);
                }
            }
        }
    }
    
    files
}

fn scan_path_executables() -> Vec<PathBuf> {
    let path_var = match env::var("PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Warning: PATH variable not found");
            return Vec::new();
        }
    };
    
    let mut executables = Vec::new();
    
    for dir in env::split_paths(&path_var) {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(metadata) = entry.metadata() {
                            let permissions = metadata.permissions();
                            if permissions.mode() & 0o111 != 0 {
                                executables.push(path);
                            }
                        }
                    }
                    
                    #[cfg(not(unix))]
                    {
                        executables.push(path);
                    }
                }
            }
        }
    }
    
    executables
}

fn get_unique_directories(files: &[PathBuf]) -> Vec<String> {
    let mut dirs = HashSet::new();
    
    for file in files {
        if let Some(parent) = file.parent() {
            dirs.insert(parent.to_string_lossy().to_string());
        }
    }
    
    let mut sorted_dirs: Vec<String> = dirs.into_iter().collect();
    sorted_dirs.sort();
    sorted_dirs
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let patterns = get_crypto_patterns();
    
    let mut output_file = None;
    let mut num_threads = num_cpus::get();
    let mut skip_next = false;
    let mut scan_args = Vec::new();
    
    for (i, arg) in args.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        
        if arg == "-o" || arg == "--output" {
            if i + 1 < args.len() {
                output_file = Some(args[i + 1].clone());
                skip_next = true;
            } else {
                eprintln!("Error: {} requires a filename argument", arg);
                std::process::exit(1);
            }
        } else if arg.starts_with("--output=") {
            output_file = Some(arg.trim_start_matches("--output=").to_string());
        } else if arg == "-j" || arg == "--jobs" {
            if i + 1 < args.len() {
                num_threads = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("Error: {} requires a number argument", arg);
                    std::process::exit(1);
                });
                skip_next = true;
            } else {
                eprintln!("Error: {} requires a number argument", arg);
                std::process::exit(1);
            }
        } else if arg.starts_with("--jobs=") {
            num_threads = arg.trim_start_matches("--jobs=").parse().unwrap_or_else(|_| {
                eprintln!("Error: --jobs requires a number argument");
                std::process::exit(1);
            });
        } else {
            scan_args.push(arg.clone());
        }
    }
    
    let writer = DualWriter::new(output_file.as_deref()).unwrap_or_else(|e| {
        eprintln!("Error: Failed to create output file: {}", e);
        std::process::exit(1);
    });
    
    if let Some(ref file) = output_file {
        eprintln!("Writing output to file: {}", file);
    }
    eprintln!("Using {} threads for scanning", num_threads);
    
    let files_to_scan: Vec<PathBuf> = if !scan_args.is_empty() {
        let mut files = Vec::new();
        for arg in &scan_args {
            let path = PathBuf::from(arg);
            if path.is_dir() {
                if let Ok(entries) = fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            files.push(p);
                        }
                    }
                }
            } else if path.is_file() {
                files.push(path);
            }
        }
        files
    } else {
        let mut files = scan_path_executables();
        
        let lib_dirs = vec![
            "/usr/lib",
            "/usr/lib64",
            "/usr/local/lib",
            "/usr/local/lib64",
            "/lib",
            "/lib64",
        ];
        
        files.extend(scan_directories(&lib_dirs));
        files
    };
    
    let unique_dirs = get_unique_directories(&files_to_scan);
    
    writer.writeln(&format!("=== Scanning {} files from {} directories ===", 
                            files_to_scan.len(), unique_dirs.len()));
    writer.writeln("");
    writer.writeln("Directories being scanned:");
    for dir in &unique_dirs {
        writer.writeln(&format!("  - {}", dir));
    }
    writer.writeln("");
    
    writer.writeln(&format!("{:<50}\t{}", "File", "Primitives"));
    writer.writeln(&format!("{:<50}\t{}", "====", "=========="));
    
    let file_handle = writer.clone_file_handle();
    let result_writer = Arc::new(ResultWriter::new(file_handle));
    
    let chunk_size = (files_to_scan.len() + num_threads - 1) / num_threads;
    let file_chunks: Vec<Vec<PathBuf>> = files_to_scan
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    
    let mut handles = vec![];
    
    for chunk in file_chunks {
        let patterns_clone = get_crypto_patterns();
        let result_writer_clone = Arc::clone(&result_writer);
        
        let handle = thread::spawn(move || {
            for file in chunk {
                if let Some(found_primitives) = scan_file(&file, &patterns_clone) {
                    let file_str = file.to_string_lossy();
                    let mut result = format!("{:<50}\t", file_str);
                    for primitive in found_primitives {
                        result.push_str(&format!("{} ", primitive));
                    }
                    result.push('\n');
                    result_writer_clone.write_result(&result);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
}