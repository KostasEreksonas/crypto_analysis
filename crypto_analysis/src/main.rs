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

// Thread-safe result writer with sequence counter
struct ResultWriter {
    file: Option<Arc<Mutex<fs::File>>>,
    counter: Arc<Mutex<usize>>,
}

impl ResultWriter {
    fn new(file_handle: Option<Arc<Mutex<fs::File>>>) -> Self {
        Self {
            file: file_handle,
            counter: Arc::new(Mutex::new(0)),
        }
    }

    fn write_result(&self, file_path: &str, primitives: &str) {
        // Get and increment counter
        let seq_num = {
            let mut counter = self.counter.lock().unwrap();
            *counter += 1;
            *counter
        };

        let result = format!("{:<6}\t{:<50}\t{}\n", seq_num, file_path, primitives);

        // Print to stdout
        print!("{}", result);
        std::io::stdout().flush().ok();

        // Write to file if available
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

        // Post-Quantum Cryptography (PQC) patterns
        CryptoPattern::new("PQC_Kyber_q", vec![0x01, 0x0D]),
        CryptoPattern::new("PQC_Kyber_n256", vec![0x00, 0x01, 0x00, 0x00]),
        CryptoPattern::new("PQC_Dilithium_q_LE", vec![0x01, 0xE0, 0x7F, 0x00]),
        CryptoPattern::new("PQC_Dilithium_q_BE", vec![0x00, 0x7F, 0xE0, 0x01]),
        CryptoPattern::new("PQC_SPHINCS_SHAKE", b"SPHINCS+".to_vec()),
        CryptoPattern::new("PQC_Falcon_q_LE", vec![0x01, 0x30]),
        CryptoPattern::new("PQC_Falcon_q_BE", vec![0x30, 0x01]),
        CryptoPattern::new("PQC_NTRU_n509", vec![0xFD, 0x01, 0x00, 0x00]),
        CryptoPattern::new("PQC_NTRU_n677", vec![0xA5, 0x02, 0x00, 0x00]),
        CryptoPattern::new("PQC_NTRU_n821", vec![0x35, 0x03, 0x00, 0x00]),
        CryptoPattern::new("PQC_SABER_q", vec![0x00, 0x20, 0x00, 0x00]),
        CryptoPattern::new("PQC_McEliece", b"mceliece".to_vec()),
        CryptoPattern::new("PQC_BIKE", b"BIKE".to_vec()),
        CryptoPattern::new("PQC_HQC", b"HQC".to_vec()),
        CryptoPattern::new("PQC_Rainbow", b"Rainbow".to_vec()),
        CryptoPattern::new("PQC_XMSS", b"XMSS".to_vec()),
        CryptoPattern::new("PQC_LMS", b"LMS".to_vec()),
        CryptoPattern::new("PQC_HSS", b"HSS".to_vec()),
        CryptoPattern::new("PQC_CSIDH", b"CSIDH".to_vec()),
        CryptoPattern::new("PQC_SQIsign", b"SQIsign".to_vec()),

        // Additional patterns from cryptoscan repository
        CryptoPattern::new("IKE_prime", vec![0xFF, 0xFF, 0xFF, 0xFF]),
        CryptoPattern::new("AES_sbox", vec![0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
        CryptoPattern::new("AES_inv_sbox", vec![0x52, 0x09, 0x6a, 0xd5]),
        CryptoPattern::new("MD5_initstate", vec![0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89]),
        CryptoPattern::new("SHA1_h", vec![0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89]),
        CryptoPattern::new("SHA256_h", vec![0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85]),
        CryptoPattern::new("SHA256_k", vec![0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91]),
        CryptoPattern::new("TEA_delta", vec![0x9e, 0x37, 0x79, 0xb9]),
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

fn traverse_filesystem(root: PathBuf, patterns: &[CryptoPattern], result_writer: Arc<ResultWriter>) {
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in walker {
        let path = entry.path();
        
        if path.is_file() {
            if let Some(found_primitives) = scan_file(&path.to_path_buf(), patterns) {
                let file_str = path.to_string_lossy();
                let primitives_str = found_primitives.join(" ");
                result_writer.write_result(&file_str, &primitives_str);
            }
        }
    }
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

    writer.writeln(&format!("{:<6}\t{:<50}\t{}", "#", "File", "Primitives"));
    writer.writeln(&format!("{:<6}\t{:<50}\t{}", "=", "====", "=========="));

    let file_handle = writer.clone_file_handle();
    let result_writer = Arc::new(ResultWriter::new(file_handle));

    if !scan_args.is_empty() {
        // User provided specific paths
        let mut handles = vec![];
        
        for arg in &scan_args {
            let path = PathBuf::from(arg);
            let patterns_clone = get_crypto_patterns();
            let result_writer_clone = Arc::clone(&result_writer);
            
            let handle = thread::spawn(move || {
                if path.is_dir() {
                    traverse_filesystem(path, &patterns_clone, result_writer_clone);
                } else if path.is_file() {
                    if let Some(found_primitives) = scan_file(&path, &patterns_clone) {
                        let file_str = path.to_string_lossy();
                        let primitives_str = found_primitives.join(" ");
                        result_writer_clone.write_result(&file_str, &primitives_str);
                    }
                }
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
    } else {
        // No arguments: scan entire filesystem from root
        #[cfg(unix)]
        let root = PathBuf::from("/");
        #[cfg(windows)]
        let root = PathBuf::from("C:\\");
        
        eprintln!("Scanning entire filesystem from {}...", root.display());
        eprintln!("Warning: This may take a very long time and requires elevated privileges for full access");
        
        traverse_filesystem(root, &patterns, result_writer);
    }
}
