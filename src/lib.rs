use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, Prefix, XPrv};
use bip39::{Language, Mnemonic, Seed};
use bitcoin_hashes::{hash160, Hash};
use clarity_repl::clarity::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
use clarity_repl::clarity::stacks_common::types::chainstate::StacksAddress;
use clarity_repl::clarity::util::secp256k1::Secp256k1PublicKey;
use libsecp256k1::PublicKey;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::env;

#[derive(Debug)]
pub enum Network {
    BTC,
    DOGE,
    ETH,
    LTC,
}
impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn get_derivation_path(network: &Network) -> DerivationPath {
    match network {
        Network::BTC => "m/44'/0'/0'/0"
            .parse::<DerivationPath>()
            .expect("unable to parse derivation path for BTC"),
        Network::DOGE => "m/44'/3'/0'/0"
            .parse()
            .expect("unable to parse derivation path for DOGE"),
        Network::ETH => "m/44'/60'/0'/0"
            .parse()
            .expect("unable to parse derivation path for ETH"),
        Network::LTC => "m/44'/2'/0'/0"
            .parse()
            .expect("unable to parse derivation path for ETH"),
    }
}

const DGPV: Prefix = Prefix::from_parts_unchecked("dgpv", 0x02FAC398);
pub fn get_key_prefix(network: &Network) -> Prefix {
    match network {
        Network::DOGE => DGPV,
        _ => Prefix::XPRV,
    }
}

pub fn get_p2pkh_prefix(network: Network) -> Option<u8> {
    match network {
        Network::BTC => Some(0),
        Network::DOGE => Some(30),
        Network::LTC => Some(48),
        _ => None,
    }
}

pub fn pub_key_to_stx_address(public_key: PublicKey) -> StacksAddress {
    let public_key = Secp256k1PublicKey::from_slice(&public_key.serialize_compressed()).unwrap();

    StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key],
    )
    .unwrap()
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

pub fn u8_array_to_hex_string(arr: &[u8]) -> String {
    let mut result = String::from("");
    for val in arr.iter() {
        result.push_str(format!("{:02x?}", val).as_ref());
    }
    result
}
const DEFAULT_ENTROPY: [u8; 32] = [
    85, 231, 105, 57, 174, 52, 198, 135, 143, 199, 229, 232, 188, 59, 96, 8, 208, 153, 37, 246,
    119, 222, 94, 3, 158, 56, 154, 1, 14, 59, 233, 15,
];

pub fn generate_random_mnemonic() -> Mnemonic {
    let mut entropy: [u8; 32] = [0; 32];

    if use_default_entropy() {
        entropy = DEFAULT_ENTROPY;
    } else {
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut entropy);
    }
    let entropy_string = u8_array_to_hex_string(&entropy);
    println!("# Entropy: {}", entropy_string);

    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
        .expect("Failed to generate mnemonic from entropy.");

    if print_private_data() {
        let phrase: &str = mnemonic.phrase();
        println!("# Mnemonic: {}", phrase);
    }
    mnemonic
}

pub fn generate_seed_from_mnemonic(mnemonic: Mnemonic) -> Seed {
    let seed = Seed::new(&mnemonic, "");
    if print_private_data() {
        println!("# seed: {}", u8_array_to_hex_string(&seed.as_bytes()));
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
        println!(
            "# BIP32 Extended Private Key from {} path:  {}",
            network.to_string(),
            extended_private_key.to_string(prefix).as_str()
        );
    }

    let child_number = ChildNumber::new(0, false).unwrap();
    extended_private_key.derive_child(child_number).unwrap()
}

pub fn pub_key_to_addr(pubkey: &[u8], network: Network) -> String {
    let mut pubkey_hash = Vec::from(hash160::Hash::hash(&pubkey).to_byte_array());
    let mut address_bytes = Vec::new();
    let prefix: u8 = get_p2pkh_prefix(network).expect("Invalid network for p2pkh.");
    address_bytes.push(prefix);
    address_bytes.append(&mut pubkey_hash);
    bitcoin::util::base58::check_encode_slice(&address_bytes)
}
