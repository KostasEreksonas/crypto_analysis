use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::{HashMap, HashSet};

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

#[derive(Clone, Debug)]
struct FileResult {
    path: PathBuf,
    primitives: Vec<String>,
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

    fn clone_file_handle(&self) -> Option<Arc<Mutex<fs::File>>> {
        self.file.clone()
    }
}

// Thread-safe result collector
struct ResultCollector {
    results: Arc<Mutex<Vec<FileResult>>>,
}

impl ResultCollector {
    fn new() -> Self {
        Self {
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_result(&self, path: PathBuf, primitives: Vec<String>) {
        let mut results = self.results.lock().unwrap();
        results.push(FileResult { path, primitives });
    }

    fn get_results(&self) -> Vec<FileResult> {
        let results = self.results.lock().unwrap();
        results.clone()
    }

    fn clone_collector(&self) -> Self {
        Self {
            results: Arc::clone(&self.results),
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

        // Post-Quantum Cryptography patterns
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

        // Additional patterns
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

#[cfg(unix)]
fn get_linked_libraries(binary_path: &Path) -> Vec<PathBuf> {
    let output = Command::new("ldd")
        .arg(binary_path)
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut libraries = Vec::new();

            for line in stdout.lines() {
                if let Some(path_part) = line.split("=>").nth(1) {
                    let path_str = path_part.trim().split_whitespace().next();
                    if let Some(path_str) = path_str {
                        let lib_path = PathBuf::from(path_str);
                        if lib_path.exists() && lib_path.is_file() {
                            libraries.push(lib_path);
                        }
                    }
                } else if line.trim().starts_with('/') {
                    let path_str = line.trim().split_whitespace().next();
                    if let Some(path_str) = path_str {
                        let lib_path = PathBuf::from(path_str);
                        if lib_path.exists() && lib_path.is_file() {
                            libraries.push(lib_path);
                        }
                    }
                }
            }

            return libraries;
        }
    }

    Vec::new()
}

#[cfg(not(unix))]
fn get_linked_libraries(_binary_path: &Path) -> Vec<PathBuf> {
    Vec::new()
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let permissions = metadata.permissions();
            return permissions.mode() & 0o111 != 0;
        }
    }
    #[cfg(not(unix))]
    {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            return ext_str == "exe" || ext_str == "dll";
        }
    }
    false
}

fn traverse_filesystem(root: PathBuf) -> Vec<PathBuf> {
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok());

    let mut files = Vec::new();
    for entry in walker {
        let path = entry.path();
        if path.is_file() {
            files.push(path.to_path_buf());
        }
    }
    files
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

fn organize_by_binaries_and_libs(results: &[FileResult], writer: &DualWriter) {
    // Create a map of path -> primitives
    let mut result_map: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for result in results {
        result_map.insert(result.path.clone(), result.primitives.clone());
    }

    // Separate executables from libraries
    let mut executables = Vec::new();
    let mut libraries = HashSet::new();

    for result in results {
        if is_executable(&result.path) {
            executables.push(result.path.clone());
        } else {
            libraries.insert(result.path.clone());
        }
    }

    writer.writeln("");
    writer.writeln("=== Organized by Binaries and Their Libraries ===");
    writer.writeln("");

    let mut binary_count = 0;

    for exe_path in &executables {
        let linked_libs = get_linked_libraries(exe_path);
        
        // Check if this executable or any of its libraries have crypto
        let exe_has_crypto = result_map.contains_key(exe_path);
        let libs_with_crypto: Vec<_> = linked_libs.iter()
            .filter(|lib| result_map.contains_key(*lib))
            .collect();

        if exe_has_crypto || !libs_with_crypto.is_empty() {
            binary_count += 1;
            writer.writeln(&format!("Binary #{}: {}", binary_count, exe_path.display()));
            
            if let Some(primitives) = result_map.get(exe_path) {
                writer.writeln(&format!("  Primitives: {}", primitives.join(", ")));
            } else {
                writer.writeln("  Primitives: (none)");
            }

            if !libs_with_crypto.is_empty() {
                writer.writeln("  Linked libraries with crypto:");
                for lib in libs_with_crypto {
                    writer.writeln(&format!("    - {}", lib.display()));
                    if let Some(primitives) = result_map.get(lib) {
                        writer.writeln(&format!("      Primitives: {}", primitives.join(", ")));
                    }
                }
            }
            writer.writeln("");
        }
    }

    writer.writeln(&format!("Total binaries with crypto: {}", binary_count));
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
                files.extend(traverse_filesystem(path));
            } else if path.is_file() {
                files.push(path);
            }
        }
        files
    } else {
        #[cfg(unix)]
        let root = PathBuf::from("/");
        #[cfg(windows)]
        let root = PathBuf::from("C:\\");
        
        eprintln!("Scanning entire filesystem from {}...", root.display());
        traverse_filesystem(root)
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

    writer.writeln(&format!("{:<6}\t{:<50}\t{}", "#", "File", "Primitives"));
    writer.writeln(&format!("{:<6}\t{:<50}\t{}", "=", "====", "=========="));

    // Collect results during scan
    let collector = ResultCollector::new();

    let chunk_size = (files_to_scan.len() + num_threads - 1) / num_threads;
    let file_chunks: Vec<Vec<PathBuf>> = files_to_scan
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    let mut handles = vec![];
    let counter = Arc::new(Mutex::new(0usize));

    for chunk in file_chunks {
        let patterns_clone = get_crypto_patterns();
        let collector_clone = collector.clone_collector();
        let counter_clone = Arc::clone(&counter);

        let handle = thread::spawn(move || {
            for file in chunk {
                if let Some(found_primitives) = scan_file(&file, &patterns_clone) {
                    let primitives_vec: Vec<String> = found_primitives.iter()
                        .map(|s| s.to_string())
                        .collect();
                    
                    // Get sequence number
                    let seq_num = {
                        let mut counter = counter_clone.lock().unwrap();
                        *counter += 1;
                        *counter
                    };

                    let file_str = file.to_string_lossy();
                    let primitives_str = primitives_vec.join(" ");
                    println!("{:<6}\t{:<50}\t{}", seq_num, file_str, primitives_str);
                    
                    collector_clone.add_result(file.clone(), primitives_vec);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Get all results
    let results = collector.get_results();
    
    writer.writeln("");
    writer.writeln(&format!("=== Scan Complete: {} files with crypto primitives ===", results.len()));

    // Organize and display by binaries and libraries
    organize_by_binaries_and_libs(&results, &writer);
}
