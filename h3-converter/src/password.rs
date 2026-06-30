use crate::{field_from_decimal, field_to_decimal};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zk_regex_compiler::{NFAGraph, ProverInputs, ProvingFramework, gen_circuit_inputs};

pub const PASSWORD_MIN_BYTES: usize = 8;
pub const PASSWORD_MAX_BYTES: usize = 32;
pub const PASSWORD_MAX_HAYSTACK_BYTES: usize = 35;
pub const PASSWORD_MAX_MATCH_BYTES: usize = 34;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordPolicyInput {
    #[serde(rename = "inHaystack")]
    pub in_haystack: Vec<u8>,
    #[serde(rename = "matchStart")]
    pub match_start: usize,
    #[serde(rename = "matchLength")]
    pub match_length: usize,
    #[serde(rename = "lowerCurrStates")]
    pub lower_curr_states: Vec<usize>,
    #[serde(rename = "lowerNextStates")]
    pub lower_next_states: Vec<usize>,
    #[serde(rename = "upperCurrStates")]
    pub upper_curr_states: Vec<usize>,
    #[serde(rename = "upperNextStates")]
    pub upper_next_states: Vec<usize>,
    #[serde(rename = "digitCurrStates")]
    pub digit_curr_states: Vec<usize>,
    #[serde(rename = "digitNextStates")]
    pub digit_next_states: Vec<usize>,
    #[serde(rename = "specialCurrStates")]
    pub special_curr_states: Vec<usize>,
    #[serde(rename = "specialNextStates")]
    pub special_next_states: Vec<usize>,
    #[serde(rename = "lengthCurrStates")]
    pub length_curr_states: Vec<usize>,
    #[serde(rename = "lengthNextStates")]
    pub length_next_states: Vec<usize>,
    pub salt: String,
    #[serde(rename = "passwordCommitment")]
    pub password_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicyBuildDetails {
    pub input: PasswordPolicyInput,
    pub regex_input: String,
    pub password_padded: Vec<u8>,
    pub chunk0: String,
    pub chunk1: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordInputErrorStage {
    CharacterCheck,
    LengthCheck,
    DfaNoMatch,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordInputError {
    pub stage: PasswordInputErrorStage,
    pub message: String,
}

impl PasswordInputError {
    fn new(stage: PasswordInputErrorStage, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PasswordInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.stage, self.message)
    }
}

impl std::error::Error for PasswordInputError {}

#[derive(Debug, Clone)]
struct ModulePaths {
    lower: PathBuf,
    upper: PathBuf,
    digit: PathBuf,
    special: PathBuf,
    length: PathBuf,
}

struct ModuleGraphJsons<'a> {
    lower: &'a str,
    upper: &'a str,
    digit: &'a str,
    special: &'a str,
    length: &'a str,
}

#[derive(Debug, Clone)]
struct RegexPathInput {
    in_haystack: Vec<u8>,
    match_start: usize,
    match_length: usize,
    curr_states: Vec<usize>,
    next_states: Vec<usize>,
}

pub fn generate_password_policy_input_from_graph_dir(
    graph_root: impl AsRef<Path>,
    password: &str,
    salt: &str,
) -> Result<PasswordPolicyBuildDetails, PasswordInputError> {
    let graph_root = graph_root.as_ref();
    let paths = ModulePaths {
        lower: graph_root.join("lowercase/password_lowercase_regex_graph.json"),
        upper: graph_root.join("uppercase/password_uppercase_regex_graph.json"),
        digit: graph_root.join("digit/password_digit_regex_graph.json"),
        special: graph_root.join("special/password_special_regex_graph.json"),
        length: graph_root.join("length/password_length_regex_graph.json"),
    };
    generate_password_policy_input_from_graphs(&paths, password, salt)
}

pub fn generate_len8_benchmark_input_json() -> Result<String, PasswordInputError> {
    generate_benchmark_input_json(8)
}

pub fn generate_benchmark_input_json(password_length: usize) -> Result<String, PasswordInputError> {
    let (password, salt) = match password_length {
        8 => ("Aa1!bbbb", "1008"),
        16 => ("Aa1!bbbbbbbbbbbb", "1016"),
        32 => ("Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbb", "1032"),
        _ => {
            return Err(PasswordInputError::new(
                PasswordInputErrorStage::LengthCheck,
                format!("unsupported benchmark password length: {password_length}"),
            ));
        }
    };
    let details = generate_password_policy_input_from_embedded_graphs(password, salt)?;
    serde_json::to_string(&details.input).map_err(|error| {
        PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("failed to serialize password benchmark input: {error}"),
        )
    })
}

pub fn generate_registration_input_json(
    password: &str,
    salt: &str,
) -> Result<String, PasswordInputError> {
    validate_salt(salt)?;
    let details = generate_password_policy_input_from_embedded_graphs(password, salt)?;
    serde_json::to_string(&details.input).map_err(|error| {
        PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("failed to serialize password registration input: {error}"),
        )
    })
}

fn generate_password_policy_input_from_embedded_graphs(
    password: &str,
    salt: &str,
) -> Result<PasswordPolicyBuildDetails, PasswordInputError> {
    let graphs = ModuleGraphJsons {
        lower: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/password-dfa/lowercase/password_lowercase_regex_graph.json"
        )),
        upper: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/password-dfa/uppercase/password_uppercase_regex_graph.json"
        )),
        digit: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/password-dfa/digit/password_digit_regex_graph.json"
        )),
        special: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/password-dfa/special/password_special_regex_graph.json"
        )),
        length: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/password-dfa/length/password_length_regex_graph.json"
        )),
    };
    generate_password_policy_input_from_graph_jsons(&graphs, password, salt)
}

fn generate_password_policy_input_from_graphs(
    paths: &ModulePaths,
    password: &str,
    salt: &str,
) -> Result<PasswordPolicyBuildDetails, PasswordInputError> {
    let lower = read_graph_json(&paths.lower)?;
    let upper = read_graph_json(&paths.upper)?;
    let digit = read_graph_json(&paths.digit)?;
    let special = read_graph_json(&paths.special)?;
    let length = read_graph_json(&paths.length)?;
    let graphs = ModuleGraphJsons {
        lower: &lower,
        upper: &upper,
        digit: &digit,
        special: &special,
        length: &length,
    };
    generate_password_policy_input_from_graph_jsons(&graphs, password, salt)
}

fn generate_password_policy_input_from_graph_jsons(
    graphs: &ModuleGraphJsons,
    password: &str,
    salt: &str,
) -> Result<PasswordPolicyBuildDetails, PasswordInputError> {
    let password_bytes = validate_password(password)?;
    let regex_input = format!("P{};", password);
    let lower = generate_module_input("lower", graphs.lower, &regex_input)?;
    let upper = generate_module_input("upper", graphs.upper, &regex_input)?;
    let digit = generate_module_input("digit", graphs.digit, &regex_input)?;
    let special = generate_module_input("special", graphs.special, &regex_input)?;
    let length = generate_module_input("length", graphs.length, &regex_input)?;

    ensure_shared_fields_match("upper", &lower, &upper)?;
    ensure_shared_fields_match("digit", &lower, &digit)?;
    ensure_shared_fields_match("special", &lower, &special)?;
    ensure_shared_fields_match("length", &lower, &length)?;

    if lower.match_start != 0 {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("unexpected matchStart {}", lower.match_start),
        ));
    }
    let expected_match_length = password_bytes.len() + 2;
    if lower.match_length != expected_match_length {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!(
                "unexpected matchLength {}, expected {}",
                lower.match_length, expected_match_length
            ),
        ));
    }

    let password_padded = password_padded(password_bytes);
    let chunk0 = pack_le(&password_padded[..16])?;
    let chunk1 = pack_le(&password_padded[16..])?;
    let password_commitment =
        password_poseidon_commitment(&chunk0, &chunk1, password_bytes.len(), salt)?;

    Ok(PasswordPolicyBuildDetails {
        input: PasswordPolicyInput {
            in_haystack: lower.in_haystack,
            match_start: lower.match_start,
            match_length: lower.match_length,
            lower_curr_states: lower.curr_states,
            lower_next_states: lower.next_states,
            upper_curr_states: upper.curr_states,
            upper_next_states: upper.next_states,
            digit_curr_states: digit.curr_states,
            digit_next_states: digit.next_states,
            special_curr_states: special.curr_states,
            special_next_states: special.next_states,
            length_curr_states: length.curr_states,
            length_next_states: length.next_states,
            salt: salt.to_string(),
            password_commitment,
        },
        regex_input,
        password_padded,
        chunk0,
        chunk1,
    })
}

pub fn password_poseidon_commitment(
    chunk0: &str,
    chunk1: &str,
    password_length: usize,
    salt: &str,
) -> Result<String, PasswordInputError> {
    let inputs = [
        field_from_decimal(chunk0).map_err(other_error)?,
        field_from_decimal(chunk1).map_err(other_error)?,
        field_from_decimal(&password_length.to_string()).map_err(other_error)?,
        field_from_decimal(salt).map_err(|_| {
            PasswordInputError::new(
                PasswordInputErrorStage::Other,
                "salt is not a valid BN254 scalar field element",
            )
        })?,
    ];
    let mut poseidon = Poseidon::<Fr>::new_circom(4).map_err(|error| {
        PasswordInputError::new(PasswordInputErrorStage::Other, error.to_string())
    })?;
    let commitment = poseidon.hash(&inputs).map_err(|error| {
        PasswordInputError::new(PasswordInputErrorStage::Other, error.to_string())
    })?;
    Ok(field_to_decimal(&commitment))
}

pub fn compute_password_commitment(
    password: &str,
    salt: &str,
) -> Result<String, PasswordInputError> {
    validate_salt(salt)?;
    let (chunk0, chunk1) = password_chunks(password)?;
    password_poseidon_commitment(&chunk0, &chunk1, password.len(), salt)
}

fn validate_salt(salt: &str) -> Result<(), PasswordInputError> {
    if salt.is_empty()
        || !salt.bytes().all(|byte| byte.is_ascii_digit())
        || (salt.len() > 1 && salt.starts_with('0'))
    {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            "salt must be a non-empty decimal integer",
        ));
    }
    let value = BigUint::parse_bytes(salt.as_bytes(), 10).ok_or_else(|| {
        PasswordInputError::new(
            PasswordInputErrorStage::Other,
            "salt decimal parsing failed",
        )
    })?;
    if value == BigUint::from(0u8) {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            "salt must be non-zero",
        ));
    }
    let modulus = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    if value >= modulus {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            "salt must be smaller than the BN254 scalar field modulus",
        ));
    }
    Ok(())
}

pub fn password_chunks(password: &str) -> Result<(String, String), PasswordInputError> {
    let password_bytes = validate_password(password)?;
    let padded = password_padded(password_bytes);
    Ok((pack_le(&padded[..16])?, pack_le(&padded[16..])?))
}

fn validate_password(password: &str) -> Result<&[u8], PasswordInputError> {
    let bytes = password.as_bytes();
    if !password.is_ascii() {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::CharacterCheck,
            "password must contain ASCII bytes only",
        ));
    }
    if bytes.len() < PASSWORD_MIN_BYTES || bytes.len() > PASSWORD_MAX_BYTES {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::LengthCheck,
            format!(
                "password length {} is outside {}..{} bytes",
                bytes.len(),
                PASSWORD_MIN_BYTES,
                PASSWORD_MAX_BYTES
            ),
        ));
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;
    for byte in bytes {
        match byte {
            b'a'..=b'z' => has_lower = true,
            b'A'..=b'Z' => has_upper = true,
            b'0'..=b'9' => has_digit = true,
            b'!' | b'@' | b'#' | b'$' | b'%' | b'^' | b'&' | b'*' => has_special = true,
            _ => {
                return Err(PasswordInputError::new(
                    PasswordInputErrorStage::CharacterCheck,
                    format!("unsupported password byte {}", byte),
                ));
            }
        }
    }
    if !has_upper {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::CharacterCheck,
            "password must contain at least one uppercase letter",
        ));
    }
    if !has_lower {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::CharacterCheck,
            "password must contain at least one lowercase letter",
        ));
    }
    if !has_digit {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::CharacterCheck,
            "password must contain at least one digit",
        ));
    }
    if !has_special {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::CharacterCheck,
            "password must contain at least one allowed special byte",
        ));
    }
    Ok(bytes)
}

fn password_padded(password_bytes: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; PASSWORD_MAX_BYTES];
    padded[..password_bytes.len()].copy_from_slice(password_bytes);
    padded
}

fn pack_le(bytes: &[u8]) -> Result<String, PasswordInputError> {
    let mut result = BigUint::from(0u8);
    let mut factor = BigUint::from(1u16);
    for byte in bytes {
        result += BigUint::from(*byte) * &factor;
        factor <<= 8usize;
    }
    if result >= BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be()) {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            "packed password chunk exceeds BN254 scalar field",
        ));
    }
    Ok(result.to_string())
}

fn read_graph_json(graph_path: &Path) -> Result<String, PasswordInputError> {
    std::fs::read_to_string(graph_path).map_err(|error| {
        PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("failed to read graph {}: {error}", graph_path.display()),
        )
    })
}

fn generate_module_input(
    module: &str,
    graph_json: &str,
    regex_input: &str,
) -> Result<RegexPathInput, PasswordInputError> {
    let graph = NFAGraph::from_json(&graph_json).map_err(|error| {
        PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("failed to parse {module} graph: {error}"),
        )
    })?;
    let inputs = gen_circuit_inputs(
        &graph,
        regex_input,
        PASSWORD_MAX_HAYSTACK_BYTES,
        PASSWORD_MAX_MATCH_BYTES,
        ProvingFramework::Circom,
    )
    .map_err(|error| {
        let message = error.to_string();
        let stage = if message.contains("No match") || message.contains("No valid") {
            PasswordInputErrorStage::DfaNoMatch
        } else {
            PasswordInputErrorStage::Other
        };
        PasswordInputError::new(stage, message)
    })?;

    match inputs {
        ProverInputs::Circom(input) => Ok(RegexPathInput {
            in_haystack: input.in_haystack,
            match_start: input.match_start,
            match_length: input.match_length,
            curr_states: input.curr_states,
            next_states: input.next_states,
        }),
        ProverInputs::Noir(_) => Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            "unexpected Noir inputs from Circom generation",
        )),
    }
}

fn ensure_shared_fields_match(
    module: &str,
    reference: &RegexPathInput,
    candidate: &RegexPathInput,
) -> Result<(), PasswordInputError> {
    if reference.in_haystack != candidate.in_haystack {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("{module} inHaystack does not match lower module"),
        ));
    }
    if reference.match_start != candidate.match_start {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("{module} matchStart does not match lower module"),
        ));
    }
    if reference.match_length != candidate.match_length {
        return Err(PasswordInputError::new(
            PasswordInputErrorStage::Other,
            format!("{module} matchLength does not match lower module"),
        ));
    }
    Ok(())
}

fn other_error(message: String) -> PasswordInputError {
    PasswordInputError::new(PasswordInputErrorStage::Other, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;
    use std::path::Path;

    fn password_graph_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("password-dfa")
    }

    fn password_vector_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../zk-location/test-vectors/password")
    }

    fn diagnostic_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-diagnostics/password_rust_input")
    }

    struct VectorCase {
        name: &'static str,
        password: &'static str,
        salt: &'static str,
        chunk0: &'static str,
        chunk1: &'static str,
        commitment: &'static str,
    }

    fn cases() -> Vec<VectorCase> {
        vec![
            VectorCase {
                name: "len8",
                password: "Aa1!bbbb",
                salt: "1008",
                chunk0: "7089336937037783361",
                chunk1: "0",
                commitment: "19506709927157339127216134994054708157265210932536273927045978637769242245953",
            },
            VectorCase {
                name: "len16",
                password: "Aa1!bbbbbbbbbbbb",
                salt: "1016",
                chunk0: "130775184150007723213375339325625033025",
                chunk1: "0",
                commitment: "11186526345370232576299025816516415797176095098189845436645573564034254234122",
            },
            VectorCase {
                name: "len32",
                password: "Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                salt: "1032",
                chunk0: "130775184150007723213375339325625033025",
                chunk1: "130775184150007723213375339326718763618",
                commitment: "15382327428467064216367910183421615477503124169574981342044370954693189986584",
            },
        ]
    }

    #[test]
    fn password_poseidon_vectors_match() {
        for case in cases() {
            let (chunk0, chunk1) = password_chunks(case.password).unwrap();
            assert_eq!(chunk0, case.chunk0, "{} chunk0", case.name);
            assert_eq!(chunk1, case.chunk1, "{} chunk1", case.name);
            let commitment =
                password_poseidon_commitment(&chunk0, &chunk1, case.password.len(), case.salt)
                    .unwrap();
            assert_eq!(commitment, case.commitment, "{} commitment", case.name);
        }
    }

    #[test]
    fn login_commitment_matches_registration_vectors_for_all_lengths() {
        for case in cases() {
            assert_eq!(
                compute_password_commitment(case.password, case.salt).unwrap(),
                case.commitment,
                "{} login commitment",
                case.name
            );
        }
    }

    #[test]
    fn login_commitment_changes_with_password_or_salt() {
        let registered = compute_password_commitment("Aa1!bbbb", "1008").unwrap();
        let repeated = compute_password_commitment("Aa1!bbbb", "1008").unwrap();
        let changed_password = compute_password_commitment("Aa1!bbbc", "1008").unwrap();
        let changed_salt = compute_password_commitment("Aa1!bbbb", "1009").unwrap();
        assert_eq!(registered, repeated);
        assert_ne!(registered, changed_password);
        assert_ne!(registered, changed_salt);
    }

    #[test]
    fn login_commitment_rejects_invalid_passwords() {
        assert!(compute_password_commitment("Aa1!bbb", "1008").is_err());
        assert!(compute_password_commitment("Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "1008").is_err());
        assert!(compute_password_commitment("Aa1_bbbb", "1008").is_err());
    }

    #[test]
    fn login_commitment_accepts_canonical_server_salt_and_rejects_invalid_salts() {
        assert!(
            compute_password_commitment("Aa1!bbbb", "340282366920938463463374607431768211455")
                .is_ok()
        );
        for salt in [
            "",
            "0",
            "01",
            "not-decimal",
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        ] {
            assert!(
                compute_password_commitment("Aa1!bbbb", salt).is_err(),
                "{salt}"
            );
        }
    }

    #[test]
    fn password_policy_inputs_match_desktop_vectors() {
        let diag_dir = diagnostic_dir();
        let generated_dir = diag_dir.join("generated_inputs");
        fs::create_dir_all(&generated_dir).unwrap();

        let graph_root = password_graph_root();
        let mut poseidon_report = String::from(
            "case | password | salt | chunk0_match | chunk1_match | commitment_match\n",
        );
        for case in cases() {
            let details = generate_password_policy_input_from_graph_dir(
                &graph_root,
                case.password,
                case.salt,
            )
            .unwrap();
            assert_eq!(details.regex_input, format!("P{};", case.password));
            assert_eq!(details.chunk0, case.chunk0);
            assert_eq!(details.chunk1, case.chunk1);
            assert_eq!(details.input.password_commitment, case.commitment);

            let generated_json = serde_json::to_string_pretty(&details.input).unwrap() + "\n";
            fs::write(
                generated_dir.join(format!("password_policy_commitment_{}.json", case.name)),
                generated_json,
            )
            .unwrap();
            let generated_value = serde_json::to_value(&details.input).unwrap();

            let desktop_path = password_vector_root().join(format!("{}.json", case.name));
            let desktop_value: Value =
                serde_json::from_str(&fs::read_to_string(desktop_path).unwrap()).unwrap();

            let comparison = compare_values(&desktop_value, &generated_value);
            fs::write(
                diag_dir.join(format!("{}_comparison.txt", case.name)),
                comparison,
            )
            .unwrap();
            assert_required_fields_are_compatible(&desktop_value, &generated_value, case.name);

            poseidon_report.push_str(&format!(
                "{} | {} | {} | {} | {} | {}\n",
                case.name,
                case.password,
                case.salt,
                details.chunk0 == case.chunk0,
                details.chunk1 == case.chunk1,
                details.input.password_commitment == case.commitment
            ));
        }
        fs::write(diag_dir.join("poseidon_vectors.txt"), poseidon_report).unwrap();
    }

    #[test]
    fn len8_benchmark_input_uses_embedded_graphs() {
        let generated_value: Value =
            serde_json::from_str(&generate_len8_benchmark_input_json().unwrap()).unwrap();
        let desktop_path = password_vector_root().join("len8.json");
        let desktop_value: Value =
            serde_json::from_str(&fs::read_to_string(desktop_path).unwrap()).unwrap();
        assert_required_fields_are_compatible(&desktop_value, &generated_value, "len8_embedded");
        assert_eq!(
            generated_value["passwordCommitment"],
            "19506709927157339127216134994054708157265210932536273927045978637769242245953"
        );
    }

    #[test]
    fn benchmark_inputs_match_fixed_vectors() {
        for case in cases() {
            let value: Value =
                serde_json::from_str(&generate_benchmark_input_json(case.password.len()).unwrap())
                    .unwrap();
            assert_eq!(value["matchLength"], case.password.len() + 2);
            assert_eq!(value["passwordCommitment"], case.commitment);
        }
        assert!(generate_benchmark_input_json(9).is_err());
    }

    #[test]
    fn registration_salt_changes_commitment() {
        let first: Value =
            serde_json::from_str(&generate_registration_input_json("Aa1!bbbb", "1").unwrap())
                .unwrap();
        let second: Value =
            serde_json::from_str(&generate_registration_input_json("Aa1!bbbb", "2").unwrap())
                .unwrap();
        assert_ne!(first["passwordCommitment"], second["passwordCommitment"]);
        assert!(generate_registration_input_json("Aa1!bbbb", "0").is_err());
        assert!(generate_registration_input_json("Aa1!bbbb", "not-decimal").is_err());
        assert!(
            generate_registration_input_json(
                "Aa1!bbbb",
                "21888242871839275222246405745257275088548364400416034343698204186575808495617"
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_passwords_are_rejected_before_proving() {
        let graph_root = password_graph_root();
        let cases = [
            ("length_7", "Aa1!bbb", PasswordInputErrorStage::LengthCheck),
            (
                "length_33",
                "Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                PasswordInputErrorStage::LengthCheck,
            ),
            (
                "no_upper",
                "aa1!bbbb",
                PasswordInputErrorStage::CharacterCheck,
            ),
            (
                "no_lower",
                "AA1!BBBB",
                PasswordInputErrorStage::CharacterCheck,
            ),
            (
                "no_digit",
                "Aaa!bbbb",
                PasswordInputErrorStage::CharacterCheck,
            ),
            (
                "no_special",
                "Aa11bbbb",
                PasswordInputErrorStage::CharacterCheck,
            ),
            (
                "question_mark",
                "Aa1?bbbb",
                PasswordInputErrorStage::CharacterCheck,
            ),
            (
                "underscore",
                "Aa1_bbbb",
                PasswordInputErrorStage::CharacterCheck,
            ),
            ("space", "Aa1 bbbb", PasswordInputErrorStage::CharacterCheck),
            (
                "semicolon",
                "Aa1;bbbb",
                PasswordInputErrorStage::CharacterCheck,
            ),
            (
                "non_ascii",
                "Aa1!bbbé",
                PasswordInputErrorStage::CharacterCheck,
            ),
        ];
        let mut report = String::from("case | rejected | stage | message\n");
        for (name, password, expected_stage) in cases {
            let error =
                generate_password_policy_input_from_graph_dir(&graph_root, password, "1008")
                    .expect_err(name);
            report.push_str(&format!(
                "{} | true | {:?} | {}\n",
                name, error.stage, error.message
            ));
            assert_eq!(error.stage, expected_stage, "{name}");
        }
        let diag_dir = diagnostic_dir();
        fs::create_dir_all(&diag_dir).unwrap();
        fs::write(diag_dir.join("negative_tests.txt"), report).unwrap();
    }

    fn compare_values(expected: &Value, actual: &Value) -> String {
        let fields = [
            "inHaystack",
            "matchStart",
            "matchLength",
            "lowerCurrStates",
            "lowerNextStates",
            "upperCurrStates",
            "upperNextStates",
            "digitCurrStates",
            "digitNextStates",
            "specialCurrStates",
            "specialNextStates",
            "lengthCurrStates",
            "lengthNextStates",
            "salt",
            "passwordCommitment",
        ];
        let mut output = String::from("field | match | expected_len | actual_len\n");
        for field in fields {
            let expected_field = &expected[field];
            let actual_field = &actual[field];
            let expected_len = expected_field.as_array().map(|v| v.len()).unwrap_or(1);
            let actual_len = actual_field.as_array().map(|v| v.len()).unwrap_or(1);
            output.push_str(&format!(
                "{} | {} | {} | {}\n",
                field,
                expected_field == actual_field,
                expected_len,
                actual_len
            ));
        }
        output
    }

    fn assert_required_fields_are_compatible(expected: &Value, actual: &Value, case_name: &str) {
        for field in [
            "inHaystack",
            "matchStart",
            "matchLength",
            "salt",
            "passwordCommitment",
        ] {
            assert_eq!(expected[field], actual[field], "{case_name} {field}");
        }

        for field in [
            "lowerCurrStates",
            "lowerNextStates",
            "upperCurrStates",
            "upperNextStates",
            "digitCurrStates",
            "digitNextStates",
            "specialCurrStates",
            "specialNextStates",
            "lengthCurrStates",
            "lengthNextStates",
        ] {
            assert_eq!(
                expected[field].as_array().unwrap().len(),
                actual[field].as_array().unwrap().len(),
                "{case_name} {field} length"
            );
        }
    }
}
