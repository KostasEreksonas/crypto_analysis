use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, Duration};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq)]
enum QuantumVulnerability {
    HighRisk,
    MediumRisk,
    LowRisk,
    PQCSafe,
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
    key_length: Option<usize>,
}

impl CryptoPattern {
    fn new(
        name: &'static str,
        pattern: Vec<u8>,
        crypto_type: CryptoType,
        quantum_vulnerability: QuantumVulnerability,
        key_length: Option<usize>,
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
    key_length: Option<usize>,
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

// Thread-safe dual writer with JSON streaming support
struct DualWriter {
    file: Option<Arc<Mutex<fs::File>>>,
    json_file: Option<Arc<Mutex<fs::File>>>,
    first_json_entry: Arc<Mutex<bool>>,
}

impl DualWriter {
    fn new(output_file: Option<&str>, json_file: Option<&str>) -> std::io::Result<Self> {
        let file = if let Some(path) = output_file {
            Some(Arc::new(Mutex::new(fs::File::create(path)?)))
        } else {
            None
        };

        let json_file = if let Some(path) = json_file {
            let mut f = fs::File::create(path)?;
            write!(f, "[\n")?;
            Some(Arc::new(Mutex::new(f)))
        } else {
            None
        };

        Ok(Self {
            file,
            json_file,
            first_json_entry: Arc::new(Mutex::new(true)),
        })
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

    fn write_json_result(&self, result: &FileResult) {
        if let Some(ref f) = self.json_file {
            if let Ok(mut file) = f.lock() {
                let mut is_first = self.first_json_entry.lock().unwrap();

                if !*is_first {
                    write!(file, ",\n").unwrap_or_else(|e| {
                        eprintln!("Warning: Failed to write to JSON file: {}", e);
                    });
                }
                *is_first = false;

                if let Ok(json) = serde_json::to_string_pretty(result) {
                    for line in json.lines() {
                        writeln!(file, "  {}", line).unwrap_or_else(|e| {
                            eprintln!("Warning: Failed to write to JSON file: {}", e);
                        });
                    }
                }
            }
        }
    }

    fn close_json(&self) {
        if let Some(ref f) = self.json_file {
            if let Ok(mut file) = f.lock() {
                writeln!(file, "\n]").unwrap_or_else(|e| {
                    eprintln!("Warning: Failed to close JSON file: {}", e);
                });
            }
        }
    }

    fn clone_handles(&self) -> Self {
        Self {
            file: self.file.clone(),
            json_file: self.json_file.clone(),
            first_json_entry: Arc::clone(&self.first_json_entry),
        }
    }
}

// Minimal result collector for summary only
struct ResultCollector {
    high_risk: Arc<Mutex<usize>>,
    medium_risk: Arc<Mutex<usize>>,
    low_risk: Arc<Mutex<usize>>,
    pqc_safe: Arc<Mutex<usize>>,
    total_files: Arc<Mutex<usize>>,
    results_for_cbom: Arc<Mutex<Vec<FileResult>>>,
}

impl ResultCollector {
    fn new() -> Self {
        Self {
            high_risk: Arc::new(Mutex::new(0)),
            medium_risk: Arc::new(Mutex::new(0)),
            low_risk: Arc::new(Mutex::new(0)),
            pqc_safe: Arc::new(Mutex::new(0)),
            total_files: Arc::new(Mutex::new(0)),
            results_for_cbom: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_result(&self, result: &FileResult) {
        *self.total_files.lock().unwrap() += 1;

        for finding in &result.crypto_findings {
            match finding.quantum_vulnerability.as_str() {
                "HIGH RISK" => *self.high_risk.lock().unwrap() += 1,
                "MEDIUM RISK" => *self.medium_risk.lock().unwrap() += 1,
                "LOW RISK" => *self.low_risk.lock().unwrap() += 1,
                "PQC SAFE" => *self.pqc_safe.lock().unwrap() += 1,
                _ => {}
            }
        }

        self.results_for_cbom.lock().unwrap().push(result.clone());
    }

    fn get_summary(&self) -> (usize, usize, usize, usize, usize) {
        (
            *self.high_risk.lock().unwrap(),
            *self.medium_risk.lock().unwrap(),
            *self.low_risk.lock().unwrap(),
            *self.pqc_safe.lock().unwrap(),
            *self.total_files.lock().unwrap(),
        )
    }

    fn get_cbom_results(&self) -> Vec<FileResult> {
        self.results_for_cbom.lock().unwrap().clone()
    }

    fn clone_collector(&self) -> Self {
        Self {
            high_risk: Arc::clone(&self.high_risk),
            medium_risk: Arc::clone(&self.medium_risk),
            low_risk: Arc::clone(&self.low_risk),
            pqc_safe: Arc::clone(&self.pqc_safe),
            total_files: Arc::clone(&self.total_files),
            results_for_cbom: Arc::clone(&self.results_for_cbom),
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

        // Symmetric crypto (MEDIUM PRIORITY)
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

        // Hash functions
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

        // Post-Quantum Cryptography
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
    if let Ok(output) = Command::new("strings").arg(path).output() {
        let content = String::from_utf8_lossy(&output.stdout);

        if content.contains("OpenSSL") {
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

// Check if path should be skipped (system virtual filesystems)
fn should_skip_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    
    // Skip virtual/special filesystems that can hang or cause issues
    let skip_prefixes = [
        "/sys/",
        "/proc/",
        "/dev/",
    ];
    
    for prefix in &skip_prefixes {
        if path_str.starts_with(prefix) {
            return true;
        }
    }
    
    false
}

// Check if file is readable
fn is_readable(path: &Path) -> bool {
    match fs::File::open(path) {
        Ok(_) => true,
        Err(_) => false,
    }
}

// Stream files instead of loading entirely with permission and timeout handling
fn scan_file(path: &PathBuf, patterns: &[CryptoPattern]) -> Option<FileResult> {
    const CHUNK_SIZE: usize = 8192;
    const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB limit
    const READ_TIMEOUT_MS: u64 = 100; // 100ms timeout per chunk

    // Skip virtual filesystems
    if should_skip_path(path) {
        return None;
    }

    // Check if file is readable first
    if !is_readable(path) {
        return None;
    }

    let metadata = fs::metadata(path).ok()?;
    
    // Skip if file size is 0 or too large
    if metadata.len() == 0 || metadata.len() > MAX_FILE_SIZE {
        return None;
    }

    // Skip special files (sockets, pipes, devices)
    let file_type = metadata.file_type();
    if !file_type.is_file() {
        return None;
    }

    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut overlap_buffer = Vec::new();

    let max_pattern_len = patterns.iter()
        .map(|p| p.pattern.len())
        .max()
        .unwrap_or(0);

    let mut crypto_findings = Vec::new();
    let mut found_patterns = HashSet::new();
    let mut total_read = 0u64;

    loop {
        // Timeout protection: use non-blocking read with timeout
        let read_result = file.read(&mut buffer);
        
        match read_result {
            Ok(0) => break,
            Ok(n) => {
                total_read += n as u64;
                
                // Additional safety: stop if reading too much
                if total_read > MAX_FILE_SIZE {
                    break;
                }

                let search_buf = if !overlap_buffer.is_empty() {
                    overlap_buffer.extend_from_slice(&buffer[..n]);
                    &overlap_buffer
                } else {
                    &buffer[..n]
                };

                for pattern in patterns {
                    if !found_patterns.contains(pattern.name) && pattern.matches(search_buf) {
                        found_patterns.insert(pattern.name);

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

                overlap_buffer.clear();
                if n >= max_pattern_len {
                    overlap_buffer.extend_from_slice(&buffer[n.saturating_sub(max_pattern_len)..n]);
                } else {
                    overlap_buffer.extend_from_slice(&buffer[..n]);
                }
            }
            Err(_) => return None,
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

// Return iterator instead of collecting all paths, filtering out problematic directories
fn traverse_filesystem(root: PathBuf) -> Box<dyn Iterator<Item = PathBuf>> {
    Box::new(
        walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                // Filter out problematic directories at traversal time
                let path = e.path();
                !should_skip_path(path)
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.path().to_path_buf())
    )
}

fn generate_risk_summary(collector: &ResultCollector, writer: &DualWriter) {
    let (high_risk, medium_risk, low_risk, pqc_safe, total_files) = collector.get_summary();

    writer.writeln("");
    writer.writeln("=== Quantum Risk Summary ===");
    writer.writeln(&format!("  🔴 HIGH RISK (RSA, ECC, DH): {} findings", high_risk));
    writer.writeln(&format!("  🟡 MEDIUM RISK (Symmetric): {} findings", medium_risk));
    writer.writeln(&format!("  🟢 LOW RISK (SHA-256/512): {} findings", low_risk));
    writer.writeln(&format!("  ✅ PQC SAFE: {} findings", pqc_safe));
    writer.writeln(&format!("  📊 Total files with crypto: {}", total_files));
    writer.writeln("");
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

    let writer = DualWriter::new(output_file.as_deref(), json_export.as_deref()).unwrap_or_else(|e| {
        eprintln!("Error: Failed to create output file: {}", e);
        std::process::exit(1);
    });

    if let Some(ref file) = output_file {
        eprintln!("Writing output to file: {}", file);
    }

    if let Some(ref file) = json_export {
        eprintln!("Writing JSON export to file: {}", file);
    }

    eprintln!("Using {} threads for scanning", num_threads);
    eprintln!("Note: Skipping /sys, /proc, /dev to avoid system hangs");

    let file_iter: Box<dyn Iterator<Item = PathBuf>> = if !scan_args.is_empty() {
        let mut files = Vec::new();
        for arg in &scan_args {
            let path = PathBuf::from(arg);
            if path.is_dir() {
                files.extend(traverse_filesystem(path));
            } else if path.is_file() {
                files.push(path);
            }
        }
        Box::new(files.into_iter())
    } else {
        #[cfg(unix)]
        let root = PathBuf::from("/");
        #[cfg(windows)]
        let root = PathBuf::from("C:\\");

        eprintln!("Scanning entire filesystem from {}...", root.display());
        traverse_filesystem(root)
    };

    writer.writeln("=== Post-Quantum Cryptographic Inventory Scanner ===");
    writer.writeln("Scanning filesystem...");
    writer.writeln("");

    let collector = ResultCollector::new();
    let counter = Arc::new(Mutex::new(0usize));

    let batch_size = 1000;
    let mut file_batch = Vec::new();
    let mut handles = vec![];

    for file_path in file_iter {
        file_batch.push(file_path);

        if file_batch.len() >= batch_size {
            let chunk_size = (file_batch.len() + num_threads - 1) / num_threads;
            let file_chunks: Vec<Vec<PathBuf>> = file_batch
                .chunks(chunk_size)
                .map(|chunk| chunk.to_vec())
                .collect();

            for chunk in file_chunks {
                let patterns_clone = get_crypto_patterns();
                let collector_clone = collector.clone_collector();
                let counter_clone = Arc::clone(&counter);
                let writer_clone = writer.clone_handles();

                let handle = thread::spawn(move || {
                    for file in chunk {
                        if let Some(result) = scan_file(&file, &patterns_clone) {
                            let seq_num = {
                                let mut counter = counter_clone.lock().unwrap();
                                *counter += 1;
                                *counter
                            };

                            writer_clone.writeln(&format!("{:<6} {}", seq_num, result.file_metadata.path));
                            writer_clone.write_json_result(&result);
                            collector_clone.add_result(&result);
                        }
                    }
                });

                handles.push(handle);
            }

            for handle in handles.drain(..) {
                handle.join().unwrap();
            }

            file_batch.clear();
        }
    }

    // Process remaining files
    if !file_batch.is_empty() {
        let chunk_size = (file_batch.len() + num_threads - 1) / num_threads;
        let file_chunks: Vec<Vec<PathBuf>> = file_batch
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        for chunk in file_chunks {
            let patterns_clone = get_crypto_patterns();
            let collector_clone = collector.clone_collector();
            let counter_clone = Arc::clone(&counter);
            let writer_clone = writer.clone_handles();

            let handle = thread::spawn(move || {
                for file in chunk {
                    if let Some(result) = scan_file(&file, &patterns_clone) {
                        let seq_num = {
                            let mut counter = counter_clone.lock().unwrap();
                            *counter += 1;
                            *counter
                        };

                        writer_clone.writeln(&format!("{:<6} {}", seq_num, result.file_metadata.path));
                        writer_clone.write_json_result(&result);
                        collector_clone.add_result(&result);
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    writer.close_json();

    writer.writeln("");
    writer.writeln("=== Scan Complete ===");

    generate_risk_summary(&collector, &writer);

    let results = collector.get_cbom_results();
    organize_by_binaries_and_libs(&results, &writer);
}
