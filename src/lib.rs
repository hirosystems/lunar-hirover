use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, Prefix, XPrv};
use bip39::{Language, Mnemonic, Seed};
use ed25519_dalek_bip32::{
  ExtendedSecretKey as Ed25519ExtendedSecretKey,
  DerivationPath as Ed25519DerivationPath
};
use bitcoin_hashes::{hash160, Hash};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::env;
use std::num::ParseIntError;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use sha2::{Sha256, Digest};
use base58::ToBase58;

#[derive(Debug)]
pub enum Network {
    BTC,
    DOGE,
    ETH,
    LTC,
    STX,
    TEZ,
    XMR,
}

pub enum TezPrefix {
    TZ1,
    EDSK,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn get_derivation_path_str(network: &Network) -> &str {
    match network {
        Network::BTC => "m/44'/0'/0'/0",
        Network::DOGE => "m/44'/3'/0'/0",
        Network::ETH => "m/44'/60'/0'/0",
        Network::LTC => "m/44'/2'/0'/0",
        Network::STX => "m/44'/5757'/0'/0",
        Network::TEZ => "m/44'/1729'/0'/0'",
        Network::XMR => "m/44'/128'/0'/0",
    }
}

pub fn get_derivation_path(network: &Network) -> DerivationPath {
    let path = get_derivation_path_str(&network);
    path.parse::<DerivationPath>()
        .unwrap_or_else(|e| panic!("unable to parse derivation path for {}: {}", network, e))
}

pub fn get_ed25519_derivation_path(network: &Network) -> Ed25519DerivationPath {
    let path = get_derivation_path_str(&network);
    path.parse::<Ed25519DerivationPath>()
        .unwrap_or_else(|e| panic!("unable to parse derivation path for {}: {}", network, e))
}

pub fn get_tez_prefix(prefix: &TezPrefix) -> &'static [u8] {
    match prefix {
        TezPrefix::TZ1 => &[6, 161, 159],
        TezPrefix::EDSK => &[43, 246, 78, 7],
    }
}

const DGPV: Prefix = Prefix::from_parts_unchecked("dgpv", 0x02FAC398);
pub fn get_key_prefix(network: &Network) -> Prefix {
    match network {
        Network::DOGE => DGPV,
        _ => Prefix::XPRV,
    }
}

pub fn get_p2pkh_prefix(network: &Network) -> Option<u8> {
    match network {
        Network::BTC => Some(0),
        Network::DOGE => Some(30),
        Network::LTC => Some(48),
        _ => None,
    }
}

/// Checks if the `PRINT_PRIVATE_DATA` environment variable is set to
/// `TRUE` to determine if the application should print secret information,
/// such as mnemonic and account private keys.
pub fn print_private_data() -> bool {
    match env::var("PRINT_PRIVATE_DATA") {
        Ok(val) => val == "TRUE",
        _ => false,
    }
}

fn use_default_entropy() -> bool {
    match env::var("USE_DEFAULT_ENTROPY") {
        Ok(val) => val == "TRUE",
        _ => false,
    }
}

fn user_provided_entropy() -> Option<String> {
    match env::var("ENTROPY") {
        Ok(val) => Some(val),
        _ => None,
    }
}

pub fn u8_array_to_hex_string(arr: &[u8]) -> String {
    let mut result = String::from("");
    for val in arr.iter() {
        result.push_str(format!("{:02x?}", val).as_ref());
    }
    result
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

const DEFAULT_ENTROPY: [u8; 32] = [
    85, 231, 105, 57, 174, 52, 198, 135, 143, 199, 229, 232, 188, 59, 96, 8, 208, 153, 37, 246,
    119, 222, 94, 3, 158, 56, 154, 1, 14, 59, 233, 15,
];

pub fn generate_entropy() -> [u8; 32] {
    let mut entropy: [u8; 32] = [0; 32];
    let entropy_string: String;

    if user_provided_entropy().is_some() {
        eprintln!("Using user-provided entropy.");
        entropy_string = user_provided_entropy().unwrap();
        let bytes = decode_hex(&entropy_string).unwrap();
        entropy = bytes[0..32].try_into().unwrap();
    } else if use_default_entropy() {
        eprintln!("Using default entropy.");
        entropy = DEFAULT_ENTROPY;
        entropy_string = u8_array_to_hex_string(&entropy);
    } else {
        eprintln!("Using random entropy.");
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut entropy);
        entropy_string = u8_array_to_hex_string(&entropy);
        eprintln!(
            "# Partial Entropy: {}...{}",
            &entropy_string[..3],
            &entropy_string[61..]
        );
    }
    // print to stdout so it can be sent to the clipboard.
    println!("{}", entropy_string);
    if print_private_data() {
        eprintln!("# Full Entropy: {}", entropy_string);
    }
    entropy
}

pub fn generate_random_mnemonic(entropy: [u8; 32]) -> Mnemonic {
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
        .expect("Failed to generate mnemonic from entropy.");

    if print_private_data() {
        let phrase: &str = mnemonic.phrase();
        eprintln!("# Mnemonic: {}", phrase);
    }
    mnemonic
}

pub fn generate_seed_from_mnemonic(mnemonic: Mnemonic) -> Seed {
    let seed = Seed::new(&mnemonic, "");
    if print_private_data() {
        eprintln!("# seed: {}", u8_array_to_hex_string(&seed.as_bytes()));
    }
    seed
}

pub fn generate_private_key_for_path(
    network: &Network,
    seed: &Seed,
) -> ExtendedPrivateKey<bip32::secp256k1::ecdsa::SigningKey> {
    let path = get_derivation_path(network);

    let extended_private_key: XPrv =
        XPrv::derive_from_path(&seed, &path).expect("Failed to generate BTC extended private key.");

    if print_private_data() {
        let prefix = get_key_prefix(network);
        eprintln!(
            "# BIP32 Extended Private Key from {} path:  {}",
            network.to_string(),
            extended_private_key.to_string(prefix).as_str()
        );
    }

    let child_number = ChildNumber::new(0, false).unwrap();
    extended_private_key.derive_child(child_number).unwrap()
}

pub fn generate_ed25519_private_key_for_path(
    network: &Network,
    seed: &Seed,
) -> Ed25519ExtendedSecretKey {
    let path = get_ed25519_derivation_path(network);
    let extended_private_key =
        Ed25519ExtendedSecretKey::from_seed(&seed.as_bytes()).expect("Failed to generate Ed25519 extended private key.");
    extended_private_key.derive(&path).expect("Failed to generate Ed25519 extended private key.")
}

pub fn pub_key_to_addr(pubkey: &[u8], network: &Network) -> String {
    let mut pubkey_hash = Vec::from(hash160::Hash::hash(&pubkey).to_byte_array());
    let mut address_bytes = Vec::new();
    let prefix: u8 = get_p2pkh_prefix(network).expect("Invalid network for p2pkh.");
    address_bytes.push(prefix);
    address_bytes.append(&mut pubkey_hash);
    bitcoin::util::base58::check_encode_slice(&address_bytes)
}

pub fn base58check_encode(data: &[u8], prefix: &TezPrefix) -> String {
    let prefix_bytes = get_tez_prefix(prefix);
    let mut prefixed_data = Vec::with_capacity(prefix_bytes.len() + data.len());
    prefixed_data.extend(prefix_bytes);
    prefixed_data.extend(data);

    // 4 bytes checksum
    let mut payload = Vec::with_capacity(prefixed_data.len() + 4);
    payload.extend(&prefixed_data);
    let checksum = Sha256::digest(&Sha256::digest(&prefixed_data));
    payload.extend(&checksum[..4]);

    payload.to_base58()
}

pub fn tez_pub_key_to_addr(pubkey: &[u8], prefix: &TezPrefix) -> String {
    let mut hasher = Blake2bVar::new(20).expect("Failed to create new Blake2b.");
    hasher.update(&pubkey);
    let mut buf = [0u8; 20];
    hasher.finalize_variable(&mut buf).expect("Failed to hash TEZ public key.");
    base58check_encode(&buf, &prefix)
}
