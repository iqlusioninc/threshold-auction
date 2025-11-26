//! Validator node for threshold-encrypted auctions.
//!
//! This binary runs as a validator participating in:
//! - Distributed Key Generation (DKG)
//! - Producing partial decryption shares for auctions

use anyhow::{anyhow, Result};
use bls12_381::{G1Affine, G1Projective, G2Projective, Scalar};
use clap::{Parser, Subcommand};
use ff::Field;
use group::Curve;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::core::client::ClientT;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{error, info, warn};

use auction_types::compute_auction_identity;

#[derive(Parser)]
#[command(name = "validator")]
#[command(about = "Threshold auction validator node")]
struct Cli {
    /// Validator index (1-based)
    #[arg(short, long)]
    index: u32,

    /// Total number of validators
    #[arg(short = 'n', long, default_value = "3")]
    total: u32,

    /// Threshold for decryption
    #[arg(short = 't', long, default_value = "2")]
    threshold: u32,

    /// Mock chain RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    rpc: String,

    /// Path to store validator state (keys, etc.)
    #[arg(long, default_value = "./validator-data")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate keys for this validator
    Keygen,

    /// Run DKG ceremony (interactive, requires all validators online)
    Dkg {
        /// Paths to other validators' round 1 messages
        #[arg(long)]
        round1_files: Vec<PathBuf>,
    },

    /// Submit master public key and validator keys to chain
    SetupChain,

    /// Watch for auctions and produce partial decryptions
    Watch,

    /// Produce partial decryption for a specific auction
    Decrypt {
        /// Auction ID
        #[arg(long)]
        auction_id: u64,
    },

    /// Export public key
    ExportPubkey,
}

/// Validator state persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorState {
    index: u32,
    threshold: u32,
    total: u32,
    /// Secret key share (scalar) - hex encoded
    secret_share: Option<String>,
    /// Public key for this validator - hex encoded
    public_key: Option<String>,
    /// Master public key - hex encoded
    master_public_key: Option<String>,
    /// All validator public keys - (index, hex-encoded pubkey)
    validator_pubkeys: Vec<(u32, String)>,
}

impl ValidatorState {
    fn new(index: u32, threshold: u32, total: u32) -> Self {
        Self {
            index,
            threshold,
            total,
            secret_share: None,
            public_key: None,
            master_public_key: None,
            validator_pubkeys: Vec::new(),
        }
    }

    fn load(path: &PathBuf) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        std::fs::create_dir_all(path.parent().unwrap_or(path))?;
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    fn state_file(data_dir: &PathBuf, index: u32) -> PathBuf {
        data_dir.join(format!("validator-{}.json", index))
    }
}

/// Simple DKG for testing - generates coordinated keys without full protocol.
/// In production, use the full DKG protocol with message exchange.
fn generate_test_keys(index: u32, threshold: u32, total: u32, seed: u64) -> ValidatorState {
    // Use deterministic seed for reproducible test setup
    // In production, each validator would use secure randomness
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    // Generate a shared master secret (in test mode, all validators use same seed)
    let master_secret = Scalar::from_raw([seed, seed + 1, seed + 2, seed + 3]);

    // Generate polynomial coefficients for Shamir sharing
    let mut coeffs = vec![master_secret];
    for _ in 1..threshold {
        let mut bytes = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rng, &mut bytes);
        coeffs.push(Scalar::from_bytes_wide(&bytes));
    }

    // Evaluate polynomial at our index to get our share
    let x = Scalar::from(index as u64);
    let mut share = Scalar::ZERO;
    let mut x_power = Scalar::ONE;
    for coeff in &coeffs {
        share += coeff * x_power;
        x_power *= x;
    }

    // Compute public key from our share
    let public_key = (G1Projective::generator() * share).to_affine();

    // Compute master public key
    let master_pk = (G2Projective::generator() * master_secret).to_affine();

    // Generate all validator public keys
    let mut validator_pubkeys = Vec::new();
    for i in 1..=total {
        let xi = Scalar::from(i as u64);
        let mut si = Scalar::ZERO;
        let mut xi_power = Scalar::ONE;
        for coeff in &coeffs {
            si += coeff * xi_power;
            xi_power *= xi;
        }
        let pki = (G1Projective::generator() * si).to_affine();
        validator_pubkeys.push((i, hex::encode(pki.to_compressed())));
    }

    ValidatorState {
        index,
        threshold,
        total,
        secret_share: Some(hex::encode(share.to_bytes())),
        public_key: Some(hex::encode(public_key.to_compressed())),
        master_public_key: Some(hex::encode(master_pk.to_compressed())),
        validator_pubkeys,
    }
}

async fn setup_chain(client: &HttpClient, state: &ValidatorState) -> Result<()> {
    let mpk = state
        .master_public_key
        .as_ref()
        .ok_or_else(|| anyhow!("No master public key"))?;

    let validator_keys: Vec<serde_json::Value> = state
        .validator_pubkeys
        .iter()
        .map(|(idx, pk)| {
            serde_json::json!({
                "index": idx,
                "public_key": pk
            })
        })
        .collect();

    let mpk_param = serde_json::json!({
        "mpk": mpk,
        "threshold": state.threshold,
        "total_validators": state.total
    });

    let response: bool = client
        .request(
            "admin_setMasterKey",
            vec![mpk_param, serde_json::Value::Array(validator_keys)],
        )
        .await?;

    if response {
        info!("Master key and validator keys set on chain");
    } else {
        error!("Failed to set master key on chain");
    }

    Ok(())
}

async fn watch_and_decrypt(client: &HttpClient, state: &ValidatorState) -> Result<()> {
    let secret_share_hex = state
        .secret_share
        .as_ref()
        .ok_or_else(|| anyhow!("No secret share"))?;

    let secret_share_bytes: [u8; 32] = hex::decode(secret_share_hex)?
        .try_into()
        .map_err(|_| anyhow!("Invalid secret share length"))?;

    let share_scalar = Scalar::from_bytes(&secret_share_bytes);
    if share_scalar.is_none().into() {
        return Err(anyhow!("Invalid secret share"));
    }
    let share_scalar = share_scalar.unwrap();

    info!(
        "Validator {} watching for auctions to decrypt...",
        state.index
    );

    loop {
        // Get auctions that need decryption
        let auctions: Vec<AuctionInfo> = client
            .request("query_listAuctions", Vec::<()>::new())
            .await
            .unwrap_or_default();

        for auction in auctions {
            // Check if auction is in a state where we should produce partial decryption
            if auction.state == "sealed" || auction.state == "open" {
                // Check if we've already submitted for this auction
                // (In a real implementation, track this in state)

                info!(
                    "Producing partial decryption for auction {}",
                    auction.auction_id
                );

                // Compute the identity for this auction
                let identity =
                    compute_auction_identity(auction.auction_id, auction.decryption_round);

                // Generate partial signature
                match produce_partial_decryption(
                    client,
                    state.index,
                    &share_scalar,
                    auction.auction_id,
                    auction.decryption_round,
                    &identity,
                )
                .await
                {
                    Ok(_) => info!(
                        "Submitted partial decryption for auction {}",
                        auction.auction_id
                    ),
                    Err(e) => warn!(
                        "Failed to submit partial decryption for auction {}: {}",
                        auction.auction_id, e
                    ),
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

async fn produce_partial_decryption(
    client: &HttpClient,
    validator_index: u32,
    secret_share: &Scalar,
    auction_id: u64,
    round: u64,
    identity: &[u8; 32],
) -> Result<()> {
    // Hash identity to G1
    let id_point = hash_to_g1(identity);

    // Compute partial signature: σ_i = sk_i * H(identity)
    let partial_sig = (G1Projective::from(id_point) * secret_share).to_affine();

    // Generate DLEQ proof (simplified for test - in production use proper DLEQ)
    let (challenge, response) = generate_dleq_proof(secret_share, &id_point, &partial_sig);

    let params = serde_json::json!({
        "auction_id": auction_id,
        "round": round,
        "validator_index": validator_index,
        "partial_sig": hex::encode(partial_sig.to_compressed()),
        "proof_challenge": hex::encode(challenge.to_bytes()),
        "proof_response": hex::encode(response.to_bytes())
    });

    let _response: bool = client
        .request("auction_submitPartialDecryption", vec![params])
        .await?;

    Ok(())
}

fn generate_dleq_proof(sk: &Scalar, h: &G1Affine, sig: &G1Affine) -> (Scalar, Scalar) {
    // DLEQ proof: prove that log_g(pk) = log_h(sig)
    // This is a Schnorr-like proof
    let mut rng = OsRng;

    // Random nonce
    let k = Scalar::random(&mut rng);

    // Commitments
    let r1 = (G1Projective::generator() * k).to_affine();
    let r2 = (G1Projective::from(*h) * k).to_affine();

    // Challenge (Fiat-Shamir)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(r1.to_compressed());
    hasher.update(r2.to_compressed());
    hasher.update(h.to_compressed());
    hasher.update(sig.to_compressed());
    let hash = hasher.finalize();

    let mut challenge_bytes = [0u8; 32];
    challenge_bytes.copy_from_slice(&hash[..32]);
    let challenge = Scalar::from_bytes(&challenge_bytes).unwrap_or(Scalar::ONE);

    // Response
    let response = k - challenge * sk;

    (challenge, response)
}

fn hash_to_g1(data: &[u8]) -> G1Affine {
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"BLS12381G1_XMD:SHA-256_SSWU_RO_");
        hasher.update(data);
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);

        let scalar = Scalar::from_bytes(&bytes);
        if scalar.is_some().into() {
            let s = scalar.unwrap();
            return (G1Projective::generator() * s).to_affine();
        }
        counter += 1;
    }
}

#[derive(Debug, Deserialize)]
struct AuctionInfo {
    auction_id: u64,
    state: String,
    decryption_round: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("validator=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // Create data directory if needed
    std::fs::create_dir_all(&cli.data_dir)?;

    let state_file = ValidatorState::state_file(&cli.data_dir, cli.index);

    match cli.command {
        Commands::Keygen => {
            info!(
                "Generating keys for validator {} (threshold {}/{})",
                cli.index, cli.threshold, cli.total
            );

            // Use a common seed for test setup (in production, use proper DKG)
            let seed = 12345u64;
            let state = generate_test_keys(cli.index, cli.threshold, cli.total, seed);

            state.save(&state_file)?;

            info!("Keys generated and saved to {:?}", state_file);
            info!(
                "Public key: {}",
                state.public_key.as_deref().unwrap_or("none")
            );
            info!(
                "Master public key: {}",
                state.master_public_key.as_deref().unwrap_or("none")
            );
        }

        Commands::Dkg { round1_files: _ } => {
            info!("Running DKG ceremony (not yet implemented - use keygen for testing)");
            // Full DKG would exchange messages between validators
            // For now, use the simpler keygen command
        }

        Commands::SetupChain => {
            let state = ValidatorState::load(&state_file)?;
            let client = HttpClientBuilder::default().build(&cli.rpc)?;

            setup_chain(&client, &state).await?;
        }

        Commands::Watch => {
            let state = ValidatorState::load(&state_file)?;
            let client = HttpClientBuilder::default().build(&cli.rpc)?;

            watch_and_decrypt(&client, &state).await?;
        }

        Commands::Decrypt { auction_id } => {
            let state = ValidatorState::load(&state_file)?;
            let client = HttpClientBuilder::default().build(&cli.rpc)?;

            let secret_share_hex = state
                .secret_share
                .as_ref()
                .ok_or_else(|| anyhow!("No secret share"))?;

            let secret_share_bytes: [u8; 32] = hex::decode(secret_share_hex)?
                .try_into()
                .map_err(|_| anyhow!("Invalid secret share length"))?;

            let share_scalar = Scalar::from_bytes(&secret_share_bytes)
                .into_option()
                .ok_or_else(|| anyhow!("Invalid secret share"))?;

            // Get auction info
            let auction: Option<AuctionInfo> = client
                .request("query_getAuction", vec![auction_id])
                .await?;

            let auction = auction.ok_or_else(|| anyhow!("Auction not found"))?;

            let identity = compute_auction_identity(auction_id, auction.decryption_round);

            produce_partial_decryption(
                &client,
                state.index,
                &share_scalar,
                auction_id,
                auction.decryption_round,
                &identity,
            )
            .await?;

            info!("Partial decryption submitted for auction {}", auction_id);
        }

        Commands::ExportPubkey => {
            let state = ValidatorState::load(&state_file)?;

            if let Some(pk) = &state.public_key {
                println!("{}", pk);
            } else {
                error!("No public key found - run keygen first");
            }
        }
    }

    Ok(())
}
