use arboard::Clipboard;
use bip32::{Prefix, PrivateKey, XPrv};
use libsecp256k1::{PublicKey, SecretKey};
use lunar_hirover::{
    generate_entropy, generate_private_key_for_path, generate_random_mnemonic,
    generate_seed_from_mnemonic, print_private_data, pub_key_to_addr, pub_key_to_stx_address,
    u8_array_to_hex_string, Network,
};
use tiny_keccak::Hasher;

fn main() {
    let (entropy, entropy_string) = generate_entropy();

    let mut clipboard = Clipboard::new().unwrap();
    Clipboard::set_text(&mut clipboard, entropy_string)
        .expect("Failed to copy entropy to clipboard.");

    let mnemonic = generate_random_mnemonic(entropy);

    let seed = generate_seed_from_mnemonic(mnemonic);

    // Print root key to optionally verify some data
    {
        let root_key: XPrv = XPrv::new(&seed).unwrap();
        if print_private_data() {
            println!(
                "# BIP32 Root Key: {}",
                root_key.to_string(Prefix::XPRV).as_str()
            );
        }
    }
    // generate and print addresses for BTC/STX
    {
        let private_key = generate_private_key_for_path(&Network::BTC, &seed);
        let secret_key = SecretKey::parse_slice(&private_key.to_bytes()).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key);

        let btc_address = pub_key_to_addr(&public_key.serialize_compressed(), Network::BTC);
        let stx_address = pub_key_to_stx_address(public_key);

        println!("# STX Address: {}", stx_address.to_string());
        println!("# BTC Address: {}", btc_address);
    }
    // generate and print addresses for ETH
    {
        let private_key = generate_private_key_for_path(&Network::ETH, &seed);
        let signing_key = private_key.private_key();
        let public_key = signing_key.public_key();
        let point = public_key.to_encoded_point(false);

        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(&point.as_bytes()[1..]);

        let mut out = [0u8; 32];
        keccak.finalize(&mut out);

        println!("# ETH Address: 0x{}", u8_array_to_hex_string(&out[12..]));
        println!("# NOTE: The ETH address can be used to receive funds on the Polygon, Fantom, BNB, Optimism, and Arbitrum chains.");
    }

    // generate and print addresses for DOGE
    {
        let private_key = generate_private_key_for_path(&Network::DOGE, &seed);
        let secret_key = SecretKey::parse_slice(&private_key.to_bytes()).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key);

        let doge_address = pub_key_to_addr(&public_key.serialize_compressed(), Network::DOGE);

        println!("# DOGE Address: {}", doge_address);
    }

    // generate and print addresses for LTC
    {
        let private_key = generate_private_key_for_path(&Network::LTC, &seed);
        let secret_key = SecretKey::parse_slice(&private_key.to_bytes()).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key);

        let ltc_address = pub_key_to_addr(&public_key.serialize_compressed(), Network::LTC);

        println!("# LTC Address: {}", ltc_address);
    }
}
