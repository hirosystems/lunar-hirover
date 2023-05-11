use bip32::{Prefix, PrivateKey, XPrv};
use clarity_repl::clarity::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
use clarity_repl::clarity::stacks_common::types::chainstate::StacksAddress;
use clarity_repl::clarity::util::secp256k1::Secp256k1PublicKey;
use libsecp256k1::{PublicKey, SecretKey};
use lunar_hirover::{
    generate_entropy, generate_private_key_for_path, generate_random_mnemonic,
    generate_seed_from_mnemonic, print_private_data, pub_key_to_addr, u8_array_to_hex_string,
    generate_ed25519_private_key_for_path, base58check_encode, tez_pub_key_to_addr,
    Network, TezPrefix,
};
use tiny_keccak::Hasher;

fn main() {
    let entropy = generate_entropy();

    let mnemonic = generate_random_mnemonic(entropy);

    let seed = generate_seed_from_mnemonic(mnemonic);

    // Print root key to optionally verify some data
    if print_private_data() {
        let root_key: XPrv = XPrv::new(&seed).unwrap();
        eprintln!(
            "# BIP32 Root Key: {}",
            root_key.to_string(Prefix::XPRV).as_str()
        );
    }

    // generate and print addresses for BTC, DOGE, LTC
    [Network::BTC, Network::DOGE, Network::LTC]
        .iter()
        .for_each(|network| {
            let private_key = generate_private_key_for_path(&network, &seed);
            let secret_key = SecretKey::parse_slice(&private_key.to_bytes()).unwrap();
            let public_key = PublicKey::from_secret_key(&secret_key);

            let btc_address = pub_key_to_addr(&public_key.serialize_compressed(), network);

            eprintln!("# {} Address: {}", network, btc_address);
        });

    // generate and print addresses for STX
    {
        let private_key = generate_private_key_for_path(&Network::STX, &seed);
        let secret_key = SecretKey::parse_slice(&private_key.to_bytes()).unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key);
        let pub_key = Secp256k1PublicKey::from_slice(&public_key.serialize_compressed()).unwrap();

        let stx_address = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![pub_key],
        )
        .unwrap();
        eprintln!("# STX Address: {}", stx_address.to_string());
    }

    // generate and print addresses for XMR
    {
        let private_key = generate_private_key_for_path(&Network::XMR, &seed);

        let mut sha3 = tiny_keccak::Keccak::v256();
        tiny_keccak::Hasher::update(&mut sha3, &private_key.private_key().to_bytes());

        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::finalize(sha3, &mut hash);

        // key needs to be less than "curve order", reduce the SHA3 result to get a valid ed25519 scalar
        use monero::cryptonote::hash::Hash as MoneroHash;
        let private_spend_key = MoneroHash::as_scalar(&MoneroHash::from_slice(&hash));
        let private_view_key = MoneroHash::hash_to_scalar(&private_spend_key.as_bytes());

        let key_pair = monero::KeyPair {
            view: private_view_key,
            spend: private_spend_key,
        };

        let address =
            monero::util::address::Address::from_keypair(monero::Network::Mainnet, &key_pair);

        if print_private_data() {
            eprintln!("# XMR Private View Key: {}", private_view_key);
            eprintln!("# XMR Private Spend Key: {}", private_spend_key);
        }

        eprintln!("# XMR Address: {}", address);
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

        eprintln!("# ETH Address: 0x{}", u8_array_to_hex_string(&out[12..]));
        eprintln!("# NOTE: The ETH address can be used to receive funds on the Polygon, Fantom, BNB, Optimism, and Arbitrum chains.");
    }

    // generate and print addresses for TEZ
    {
        let private_key = generate_ed25519_private_key_for_path(&Network::TEZ, &seed);
        let public_key = private_key.public_key();

        if print_private_data() {
            let secret_key = [&private_key.secret_key.to_bytes()[..], &public_key.to_bytes()[..]].concat();
            let edsk = base58check_encode(&secret_key, &TezPrefix::EDSK);
            eprintln!("# TEZ Secret Key: {}", edsk);
        }

        let public_key_hash = tez_pub_key_to_addr(&public_key.to_bytes(), &TezPrefix::TZ1);

        eprintln!("# TEZ Address: {}", public_key_hash);
    }
}
