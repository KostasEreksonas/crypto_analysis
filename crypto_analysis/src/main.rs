use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq)]
enum QuantumVulnerability {
    HighRisk,      // RSA, ECC, DH
    MediumRisk,    // Symmetric crypto with short keys
    LowRisk,       // AES-256, SHA-3
    PQCSafe,       // Post-quantum algorithms
}

#[derive(Debug, Clone, PartialEq)]
enum CryptoType {
    Asymmetric,
    Symmetric,
    Hash,
    PostQuantum,
}

struct CryptoPattern {
    name: &'static str,
    pattern: Vec<u8>,
    crypto_type: CryptoType,
    quantum_vulnerability: QuantumVulnerability,
    key_length: Option<u32>,
}

impl CryptoPattern {
    fn new(
        name: &'static str,
        pattern: Vec<u8>,
        crypto_type: CryptoType,
        quantum_vulnerability: QuantumVulnerability,
        key_length: Option<u32>,
    ) -> Self {
        Self {
            name,
            pattern,
            crypto_type,
            quantum_vulnerability,
            key_length,
        }
    }

    fn matches(&self, content: &[u8]) -> bool {
        content.windows(self.pattern.len())
            .any(|window| window == self.pattern.as_slice())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CryptoMetadata {
    algorithm: String,
    crypto_type: String,
    quantum_vulnerability: String,
    key_length: Option<u32>,
    migration_priority: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileMetadata {
    path: String,
    file_size: u64,
    created: Option<String>,
    modified: Option<String>,
    file_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileResult {
    file_metadata: FileMetadata,
    crypto_findings: Vec<CryptoMetadata>,
    library_version: Option<String>,
    is_executable: bool,
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

    fn add_result(&self, result: FileResult) {
        let mut results = self.results.lock().unwrap();
        results.push(result);
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
        // Quantum-vulnerable asymmetric crypto (HIGH PRIORITY)
        CryptoPattern::new("RSA_e65537_BE32", vec![0x00, 0x01, 0x00, 0x01],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(2048)),
        CryptoPattern::new("RSA_e65537_LE32", vec![0x01, 0x00, 0x01, 0x00],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(2048)),
        CryptoPattern::new("RSA_e65537_BE64", vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(4096)),
        CryptoPattern::new("RSA_e65537_LE64", vec![0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(4096)),
        CryptoPattern::new("RSA_e3_BE32", vec![0x00, 0x00, 0x00, 0x03],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(1024)),
        CryptoPattern::new("RSA_e3_LE32", vec![0x03, 0x00, 0x00, 0x00],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(1024)),
        CryptoPattern::new("RSA_e17_BE32", vec![0x00, 0x00, 0x00, 0x11],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(2048)),
        CryptoPattern::new("RSA_e257_BE32", vec![0x00, 0x00, 0x01, 0x01],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(2048)),
        CryptoPattern::new("RSA_e257_LE32", vec![0x01, 0x01, 0x00, 0x00],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(2048)),

        // Elliptic Curve (HIGH PRIORITY - quantum vulnerable)
        CryptoPattern::new("curve25519", vec![
            0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9,
            0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
            0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
            0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21
        ], CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(256)),
        CryptoPattern::new("EC_curve25519", vec![0x1A, 0xD5, 0x25, 0x8F],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(256)),
        CryptoPattern::new("EC_p192", vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(192)),
        CryptoPattern::new("EC_p224", vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(224)),
        CryptoPattern::new("EC_p256", vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(256)),
        CryptoPattern::new("EC_p384", vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(384)),
        CryptoPattern::new("EC_p521", vec![0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            CryptoType::Asymmetric, QuantumVulnerability::HighRisk, Some(521)),

        // Symmetric crypto (MEDIUM PRIORITY - key length doubling needed)
        CryptoPattern::new("AES", vec![0x63, 0x7c, 0x77, 0x7b],
            CryptoType::Symmetric, QuantumVulnerability::MediumRisk, Some(128)),
        CryptoPattern::new("AES_sbox", vec![0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],
            CryptoType::Symmetric, QuantumVulnerability::MediumRisk, Some(128)),
        CryptoPattern::new("AES_inv_sbox", vec![0x52, 0x09, 0x6a, 0xd5],
            CryptoType::Symmetric, QuantumVulnerability::MediumRisk, Some(128)),
        CryptoPattern::new("ChaCha20", b"expand 32-byte k".to_vec(),
            CryptoType::Symmetric, QuantumVulnerability::LowRisk, Some(256)),
        CryptoPattern::new("BLOWFISH", vec![0xd1, 0x31, 0x0b, 0xa6],
            CryptoType::Symmetric, QuantumVulnerability::MediumRisk, Some(128)),
        CryptoPattern::new("DES", vec![0x80, 0x10, 0x80, 0x20],
            CryptoType::Symmetric, QuantumVulnerability::HighRisk, Some(56)),

        // Hash functions (LOW PRIORITY but monitor)
        CryptoPattern::new("MD5", vec![0xd7, 0x6a, 0xa4, 0x78],
            CryptoType::Hash, QuantumVulnerability::HighRisk, None),
        CryptoPattern::new("SHA1", vec![0x5a, 0x82, 0x79, 0x99],
            CryptoType::Hash, QuantumVulnerability::HighRisk, None),
        CryptoPattern::new("SHA256", vec![0xd8, 0x9e, 0x05, 0xc1],
            CryptoType::Hash, QuantumVulnerability::LowRisk, Some(256)),
        CryptoPattern::new("SHA512", vec![0xa2, 0x4d, 0x54, 0x19, 0xc8, 0x37, 0x3d, 0x8c],
            CryptoType::Hash, QuantumVulnerability::LowRisk, Some(512)),
        CryptoPattern::new("SHA3", vec![0x89, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
            CryptoType::Hash, QuantumVulnerability::LowRisk, Some(256)),

        // Post-Quantum Cryptography (PQC SAFE)
        CryptoPattern::new("PQC_Kyber_q", vec![0x01, 0x0D],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(768)),
        CryptoPattern::new("PQC_Kyber_n256", vec![0x00, 0x01, 0x00, 0x00],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(768)),
        CryptoPattern::new("PQC_Dilithium_q_LE", vec![0x01, 0xE0, 0x7F, 0x00],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(2420)),
        CryptoPattern::new("PQC_Dilithium_q_BE", vec![0x00, 0x7F, 0xE0, 0x01],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(2420)),
        CryptoPattern::new("PQC_SPHINCS_SHAKE", b"SPHINCS+".to_vec(),
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, None),
        CryptoPattern::new("PQC_Falcon_q_LE", vec![0x01, 0x30],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(512)),
        CryptoPattern::new("PQC_Falcon_q_BE", vec![0x30, 0x01],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(512)),
        CryptoPattern::new("PQC_NTRU_n509", vec![0xFD, 0x01, 0x00, 0x00],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(509)),
        CryptoPattern::new("PQC_NTRU_n677", vec![0xA5, 0x02, 0x00, 0x00],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(677)),
        CryptoPattern::new("PQC_NTRU_n821", vec![0x35, 0x03, 0x00, 0x00],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(821)),
        CryptoPattern::new("PQC_SABER_q", vec![0x00, 0x20, 0x00, 0x00],
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(256)),
        CryptoPattern::new("PQC_McEliece", b"mceliece".to_vec(),
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, Some(6960)),
        CryptoPattern::new("PQC_BIKE", b"BIKE".to_vec(),
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, None),
        CryptoPattern::new("PQC_HQC", b"HQC".to_vec(),
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, None),
        CryptoPattern::new("PQC_XMSS", b"XMSS".to_vec(),
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, None),
        CryptoPattern::new("PQC_LMS", b"LMS".to_vec(),
            CryptoType::PostQuantum, QuantumVulnerability::PQCSafe, None),
    ]
}

fn get_migration_priority(vuln: &QuantumVulnerability) -> &'static str {
    match vuln {
        QuantumVulnerability::HighRisk => "CRITICAL - Migrate by 2026",
        QuantumVulnerability::MediumRisk => "HIGH - Upgrade key length",
        QuantumVulnerability::LowRisk => "MEDIUM - Monitor",
        QuantumVulnerability::PQCSafe => "LOW - Already PQC-safe",
    }
}

fn get_file_metadata(path: &PathBuf) -> Option<FileMetadata> {
    let metadata = fs::metadata(path).ok()?;
    
    let created = metadata.created()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| format!("{}", d.as_secs()));
    
    let modified = metadata.modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| format!("{}", d.as_secs()));

    let file_type = path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("unknown")
        .to_string();

    Some(FileMetadata {
        path: path.to_string_lossy().to_string(),
        file_size: metadata.len(),
        created,
        modified,
        file_type,
    })
}

fn detect_crypto_library(path: &PathBuf) -> Option<String> {
    // Check if file links to known crypto libraries
    if let Ok(output) = Command::new("strings").arg(path).output() {
        let content = String::from_utf8_lossy(&output.stdout);
        
        if content.contains("OpenSSL") {
            // Try to extract version
            for line in content.lines() {
                if line.contains("OpenSSL") && line.contains(".") {
                    return Some(line.trim().to_string());
                }
            }
            return Some("OpenSSL (version unknown)".to_string());
        } else if content.contains("BoringSSL") {
            return Some("BoringSSL".to_string());
        } else if content.contains("libgcrypt") {
            return Some("libgcrypt".to_string());
        } else if content.contains("Crypto++") {
            return Some("Crypto++".to_string());
        }
    }
    None
}

fn scan_file(path: &PathBuf, patterns: &[CryptoPattern]) -> Option<FileResult> {
    let mut file = fs::File::open(path).ok()?;
    let mut content = Vec::new();
    file.read_to_end(&mut content).ok()?;

    let mut crypto_findings = Vec::new();
    
    for pattern in patterns {
        if pattern.matches(&content) {
            let crypto_type_str = match pattern.crypto_type {
                CryptoType::Asymmetric => "Asymmetric",
                CryptoType::Symmetric => "Symmetric",
                CryptoType::Hash => "Hash",
                CryptoType::PostQuantum => "Post-Quantum",
            }.to_string();

            let vuln_str = match pattern.quantum_vulnerability {
                QuantumVulnerability::HighRisk => "HIGH RISK",
                QuantumVulnerability::MediumRisk => "MEDIUM RISK",
                QuantumVulnerability::LowRisk => "LOW RISK",
                QuantumVulnerability::PQCSafe => "PQC SAFE",
            }.to_string();

            crypto_findings.push(CryptoMetadata {
                algorithm: pattern.name.to_string(),
                crypto_type: crypto_type_str,
                quantum_vulnerability: vuln_str,
                key_length: pattern.key_length,
                migration_priority: get_migration_priority(&pattern.quantum_vulnerability).to_string(),
            });
        }
    }

    if crypto_findings.is_empty() {
        return None;
    }

    let file_metadata = get_file_metadata(path)?;
    let library_version = detect_crypto_library(path);
    let is_executable = is_executable(path);

    Some(FileResult {
        file_metadata,
        crypto_findings,
        library_version,
        is_executable,
    })
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
    false
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

fn generate_risk_summary(results: &[FileResult], writer: &DualWriter) {
    let mut high_risk = 0;
    let mut medium_risk = 0;
    let mut low_risk = 0;
    let mut pqc_safe = 0;

    for result in results {
        for finding in &result.crypto_findings {
            match finding.quantum_vulnerability.as_str() {
                "HIGH RISK" => high_risk += 1,
                "MEDIUM RISK" => medium_risk += 1,
                "LOW RISK" => low_risk += 1,
                "PQC SAFE" => pqc_safe += 1,
                _ => {}
            }
        }
    }

    writer.writeln("");
    writer.writeln("=== Quantum Risk Summary ===");
    writer.writeln(&format!("  🔴 HIGH RISK (RSA, ECC, DH): {} findings", high_risk));
    writer.writeln(&format!("  🟡 MEDIUM RISK (Symmetric): {} findings", medium_risk));
    writer.writeln(&format!("  🟢 LOW RISK (SHA-256/512): {} findings", low_risk));
    writer.writeln(&format!("  ✅ PQC SAFE: {} findings", pqc_safe));
    writer.writeln("");
}

fn export_json_report(results: &[FileResult], filename: &str) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    fs::write(filename, json)?;
    eprintln!("JSON report exported to: {}", filename);
    Ok(())
}

fn organize_by_binaries_and_libs(results: &[FileResult], writer: &DualWriter) {
    let mut result_map: HashMap<PathBuf, FileResult> = HashMap::new();
    for result in results {
        result_map.insert(PathBuf::from(&result.file_metadata.path), result.clone());
    }

    let mut executables = Vec::new();

    for result in results {
        if result.is_executable {
            executables.push(PathBuf::from(&result.file_metadata.path));
        }
    }

    writer.writeln("");
    writer.writeln("=== CBOM: Binaries and Their Cryptographic Dependencies ===");
    writer.writeln("");

    let mut binary_count = 0;

    for exe_path in &executables {
        let linked_libs = get_linked_libraries(exe_path);
        
        let exe_has_crypto = result_map.contains_key(exe_path);
        let libs_with_crypto: Vec<_> = linked_libs.iter()
            .filter(|lib| result_map.contains_key(*lib))
            .collect();

        if exe_has_crypto || !libs_with_crypto.is_empty() {
            binary_count += 1;
            writer.writeln(&format!("Binary #{}: {}", binary_count, exe_path.display()));
            
            if let Some(exe_result) = result_map.get(exe_path) {
                for finding in &exe_result.crypto_findings {
                    writer.writeln(&format!("  ├─ {} [{}] - {}",
                        finding.algorithm,
                        finding.quantum_vulnerability,
                        finding.migration_priority));
                }
                if let Some(ref lib) = exe_result.library_version {
                    writer.writeln(&format!("  ├─ Library: {}", lib));
                }
            }

            if !libs_with_crypto.is_empty() {
                writer.writeln("  └─ Linked libraries with crypto:");
                for lib in libs_with_crypto {
                    writer.writeln(&format!("     ├─ {}", lib.display()));
                    if let Some(lib_result) = result_map.get(lib) {
                        for finding in &lib_result.crypto_findings {
                            writer.writeln(&format!("     │  ├─ {} [{}]",
                                finding.algorithm,
                                finding.quantum_vulnerability));
                        }
                    }
                }
            }
            writer.writeln("");
        }
    }

    writer.writeln(&format!("Total binaries analyzed: {}", binary_count));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let patterns = get_crypto_patterns();

    let mut output_file = None;
    let mut json_export = None;
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
            }
        } else if arg.starts_with("--output=") {
            output_file = Some(arg.trim_start_matches("--output=").to_string());
        } else if arg == "--json" {
            if i + 1 < args.len() {
                json_export = Some(args[i + 1].clone());
                skip_next = true;
            }
        } else if arg.starts_with("--json=") {
            json_export = Some(arg.trim_start_matches("--json=").to_string());
        } else if arg == "-j" || arg == "--jobs" {
            if i + 1 < args.len() {
                num_threads = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("Error: {} requires a number argument", arg);
                    std::process::exit(1);
                });
                skip_next = true;
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

    writer.writeln("=== Post-Quantum Cryptographic Inventory Scanner ===");
    writer.writeln(&format!("Scanning {} files from {} directories",
        files_to_scan.len(), unique_dirs.len()));
    writer.writeln("");

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
                if let Some(result) = scan_file(&file, &patterns_clone) {
                    let seq_num = {
                        let mut counter = counter_clone.lock().unwrap();
                        *counter += 1;
                        *counter
                    };

                    println!("{:<6} {}", seq_num, result.file_metadata.path);
                    collector_clone.add_result(result);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let results = collector.get_results();
    
    writer.writeln("");
    writer.writeln(&format!("=== Scan Complete: {} files with crypto ===", results.len()));

    generate_risk_summary(&results, &writer);
    organize_by_binaries_and_libs(&results, &writer);

    if let Some(json_file) = json_export {
        export_json_report(&results, &json_file).ok();
    }
}
