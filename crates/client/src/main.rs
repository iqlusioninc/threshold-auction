//! CLI for interacting with threshold-encrypted auctions.
//!
//! This binary provides commands for:
//! - Creating auctions
//! - Submitting encrypted bids
//! - Querying auction status
//! - Claiming refunds

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::info;

use auction_client::create_bid;
use auction_types::G2Point;

#[derive(Parser)]
#[command(name = "auction-cli")]
#[command(about = "CLI for threshold-encrypted auctions")]
struct Cli {
    /// Mock chain RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new auction
    CreateAuction {
        /// Sender address (hex)
        #[arg(long)]
        sender: String,

        /// Auction type: first_price, second_price, or gsp
        #[arg(long, default_value = "second_price")]
        auction_type: String,

        /// Start time (unix timestamp)
        #[arg(long)]
        start_time: u64,

        /// End time (unix timestamp)
        #[arg(long)]
        end_time: u64,

        /// Decryption round (block height when decryption happens)
        #[arg(long)]
        decryption_round: u64,

        /// Settlement deadline (unix timestamp)
        #[arg(long)]
        settlement_deadline: u64,

        /// Minimum bid amount
        #[arg(long, default_value = "1")]
        min_bid: u64,

        /// Reserve price (optional)
        #[arg(long)]
        reserve_price: Option<u64>,
    },

    /// Submit an encrypted bid
    Bid {
        /// Sender address (hex)
        #[arg(long)]
        sender: String,

        /// Auction ID
        #[arg(long)]
        auction_id: u64,

        /// Bid amount (will be encrypted)
        #[arg(long)]
        amount: u64,

        /// Deposit amount (visible on-chain)
        #[arg(long)]
        deposit: u64,
    },

    /// Get auction details
    GetAuction {
        /// Auction ID
        #[arg(long)]
        auction_id: u64,
    },

    /// List all auctions
    ListAuctions,

    /// Get bids for an auction
    GetBids {
        /// Auction ID
        #[arg(long)]
        auction_id: u64,
    },

    /// Get auction result
    GetResult {
        /// Auction ID
        #[arg(long)]
        auction_id: u64,
    },

    /// Get master public key
    GetMpk,

    /// Advance chain time (for testing)
    AdvanceBlock,

    /// Set chain timestamp (for testing)
    SetTimestamp {
        /// Unix timestamp to set
        #[arg(long)]
        timestamp: u64,
    },

    /// Trigger aggregation of decryption shares
    AggregateDecryption {
        /// Auction ID
        #[arg(long)]
        auction_id: u64,

        /// Decryption round
        #[arg(long)]
        round: u64,

        /// Validator indices to include (comma-separated)
        #[arg(long)]
        validators: String,
    },

    /// Settle an auction with mock proof
    Settle {
        /// Sender address (hex)
        #[arg(long)]
        sender: String,

        /// Auction ID
        #[arg(long)]
        auction_id: u64,

        /// Winner address (hex)
        #[arg(long)]
        winner: String,

        /// Winning price
        #[arg(long)]
        winning_price: u64,

        /// Winner index in bid list
        #[arg(long)]
        winner_index: u32,

        /// Number of valid bids
        #[arg(long)]
        num_valid_bids: u32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct MasterPublicKeyRpc {
    mpk: String,
    threshold: u32,
    total_validators: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuctionConfigRpc {
    auction_id: u64,
    creator: String,
    auction_type: String,
    state: String,
    start_time: u64,
    end_time: u64,
    decryption_round: u64,
    settlement_deadline: u64,
    min_bid: u64,
    reserve_price: Option<u64>,
    identity: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockInfo {
    height: u64,
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBidRpc {
    bidder: String,
    commitment: String,
    deposit: u64,
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuctionResultRpc {
    auction_id: u64,
    winner: String,
    winning_price: u64,
    num_valid_bids: u32,
    settlement_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecryptionKeyRpc {
    sigma: String,
    round: u64,
}

async fn create_auction_cmd(client: &HttpClient, params: serde_json::Value) -> Result<()> {
    let auction_id: u64 = client.request("auction_create", vec![params]).await?;
    info!("Created auction with ID: {}", auction_id);
    println!("Auction ID: {}", auction_id);
    Ok(())
}

async fn submit_bid_cmd(
    client: &HttpClient,
    sender: &str,
    auction_id: u64,
    amount: u64,
    deposit: u64,
) -> Result<()> {
    // Get master public key
    let mpk_opt: Option<MasterPublicKeyRpc> =
        client.request("query_getMasterPublicKey", Vec::<()>::new()).await?;

    let mpk = mpk_opt.ok_or_else(|| anyhow!("Master public key not set on chain"))?;

    // Parse MPK
    let mpk_bytes: [u8; 96] = hex::decode(&mpk.mpk)?
        .try_into()
        .map_err(|_| anyhow!("Invalid MPK length"))?;

    let mpk_g2 = G2Point(mpk_bytes);

    // Get auction info for decryption round
    let auction: Option<AuctionConfigRpc> = client
        .request("query_getAuction", vec![auction_id])
        .await?;

    let auction = auction.ok_or_else(|| anyhow!("Auction not found"))?;

    // Create encrypted bid
    let mut rng = OsRng;
    let prepared_bid = create_bid(&mpk_g2, auction_id, auction.decryption_round, amount, &mut rng)?;

    // Submit bid
    let params = serde_json::json!({
        "sender": sender,
        "auction_id": auction_id,
        "commitment": hex::encode(prepared_bid.commitment.point.0),
        "ciphertext": {
            "ephemeral_pubkey": hex::encode(prepared_bid.ciphertext.ephemeral_pubkey.0),
            "ciphertext": hex::encode(&prepared_bid.ciphertext.ciphertext),
            "tag": hex::encode(prepared_bid.ciphertext.tag),
            "nonce": hex::encode(prepared_bid.ciphertext.nonce)
        },
        "deposit": deposit
    });

    let _result: bool = client.request("auction_submitBid", vec![params]).await?;

    info!("Bid submitted for auction {}", auction_id);
    println!("Bid submitted successfully");
    println!("  Auction ID: {}", auction_id);
    println!("  Amount: {} (encrypted)", amount);
    println!("  Deposit: {}", deposit);

    Ok(())
}

async fn get_auction_cmd(client: &HttpClient, auction_id: u64) -> Result<()> {
    let auction: Option<AuctionConfigRpc> = client
        .request("query_getAuction", vec![auction_id])
        .await?;

    match auction {
        Some(a) => {
            println!("Auction {}:", a.auction_id);
            println!("  Type: {}", a.auction_type);
            println!("  State: {}", a.state);
            println!("  Creator: {}", a.creator);
            println!("  Start: {}", a.start_time);
            println!("  End: {}", a.end_time);
            println!("  Decryption Round: {}", a.decryption_round);
            println!("  Min Bid: {}", a.min_bid);
            if let Some(reserve) = a.reserve_price {
                println!("  Reserve: {}", reserve);
            }
        }
        None => {
            println!("Auction {} not found", auction_id);
        }
    }

    Ok(())
}

async fn list_auctions_cmd(client: &HttpClient) -> Result<()> {
    let auctions: Vec<AuctionConfigRpc> =
        client.request("query_listAuctions", Vec::<()>::new()).await?;

    if auctions.is_empty() {
        println!("No auctions found");
    } else {
        println!("Auctions:");
        for a in auctions {
            println!(
                "  [{}] {} - {} ({})",
                a.auction_id, a.auction_type, a.state, a.creator
            );
        }
    }

    Ok(())
}

async fn get_bids_cmd(client: &HttpClient, auction_id: u64) -> Result<()> {
    let bids: Vec<EncryptedBidRpc> = client
        .request("query_getAuctionBids", vec![auction_id])
        .await?;

    if bids.is_empty() {
        println!("No bids for auction {}", auction_id);
    } else {
        println!("Bids for auction {}:", auction_id);
        for (i, bid) in bids.iter().enumerate() {
            println!("  [{}] Bidder: {}", i, bid.bidder);
            println!("      Deposit: {}", bid.deposit);
            println!("      Commitment: {}...", &bid.commitment[..16]);
        }
    }

    Ok(())
}

async fn get_result_cmd(client: &HttpClient, auction_id: u64) -> Result<()> {
    let result: Option<AuctionResultRpc> = client
        .request("query_getAuctionResult", vec![auction_id])
        .await?;

    match result {
        Some(r) => {
            println!("Result for auction {}:", r.auction_id);
            println!("  Winner: {}", r.winner);
            println!("  Price: {}", r.winning_price);
            println!("  Valid Bids: {}", r.num_valid_bids);
            println!("  Settlement Time: {}", r.settlement_time);
        }
        None => {
            println!("Auction {} not settled yet", auction_id);
        }
    }

    Ok(())
}

async fn get_mpk_cmd(client: &HttpClient) -> Result<()> {
    let mpk: Option<MasterPublicKeyRpc> =
        client.request("query_getMasterPublicKey", Vec::<()>::new()).await?;

    match mpk {
        Some(m) => {
            println!("Master Public Key:");
            println!("  MPK: {}", m.mpk);
            println!("  Threshold: {}/{}", m.threshold, m.total_validators);
        }
        None => {
            println!("Master public key not set");
        }
    }

    Ok(())
}

async fn aggregate_decryption_cmd(
    client: &HttpClient,
    auction_id: u64,
    round: u64,
    validators: &str,
) -> Result<()> {
    let indices: Vec<u32> = validators
        .split(',')
        .map(|s| s.trim().parse::<u32>())
        .collect::<Result<Vec<_>, _>>()?;

    let key: DecryptionKeyRpc = client
        .request(
            "auction_aggregateDecryptionKey",
            (auction_id, round, indices),
        )
        .await?;

    println!("Decryption key aggregated:");
    println!("  Round: {}", key.round);
    println!("  Sigma: {}...", &key.sigma[..32]);

    Ok(())
}

async fn settle_cmd(
    client: &HttpClient,
    sender: &str,
    auction_id: u64,
    winner: &str,
    winning_price: u64,
    winner_index: u32,
    num_valid_bids: u32,
) -> Result<()> {
    // Get bids to compute commitments hash
    let bids: Vec<EncryptedBidRpc> = client
        .request("query_getAuctionBids", vec![auction_id])
        .await?;

    // Compute commitments hash
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for bid in &bids {
        let commitment_bytes = hex::decode(&bid.commitment)?;
        hasher.update(&commitment_bytes);
    }
    let commitments_hash: [u8; 32] = hasher.finalize().into();

    let params = serde_json::json!({
        "sender": sender,
        "auction_id": auction_id,
        "winner": winner,
        "winning_price": winning_price,
        "winner_index": winner_index,
        "num_valid_bids": num_valid_bids,
        "commitments_hash": hex::encode(commitments_hash),
        "proof_bytes": "00" // Mock proof
    });

    let result: AuctionResultRpc = client.request("auction_settle", vec![params]).await?;

    println!("Auction settled:");
    println!("  Winner: {}", result.winner);
    println!("  Price: {}", result.winning_price);
    println!("  Valid Bids: {}", result.num_valid_bids);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("auction_cli=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let client = HttpClientBuilder::default().build(&cli.rpc)?;

    match cli.command {
        Commands::CreateAuction {
            sender,
            auction_type,
            start_time,
            end_time,
            decryption_round,
            settlement_deadline,
            min_bid,
            reserve_price,
        } => {
            let params = serde_json::json!({
                "sender": sender,
                "auction_type": auction_type,
                "start_time": start_time,
                "end_time": end_time,
                "decryption_round": decryption_round,
                "settlement_deadline": settlement_deadline,
                "min_bid": min_bid,
                "reserve_price": reserve_price
            });
            create_auction_cmd(&client, params).await?;
        }

        Commands::Bid {
            sender,
            auction_id,
            amount,
            deposit,
        } => {
            submit_bid_cmd(&client, &sender, auction_id, amount, deposit).await?;
        }

        Commands::GetAuction { auction_id } => {
            get_auction_cmd(&client, auction_id).await?;
        }

        Commands::ListAuctions => {
            list_auctions_cmd(&client).await?;
        }

        Commands::GetBids { auction_id } => {
            get_bids_cmd(&client, auction_id).await?;
        }

        Commands::GetResult { auction_id } => {
            get_result_cmd(&client, auction_id).await?;
        }

        Commands::GetMpk => {
            get_mpk_cmd(&client).await?;
        }

        Commands::AdvanceBlock => {
            let info: BlockInfo = client.request("admin_advanceBlock", Vec::<()>::new()).await?;
            println!("Block advanced: height={}, timestamp={}", info.height, info.timestamp);
        }

        Commands::SetTimestamp { timestamp } => {
            let _: bool = client.request("admin_setTimestamp", vec![timestamp]).await?;
            println!("Timestamp set to {}", timestamp);
        }

        Commands::AggregateDecryption {
            auction_id,
            round,
            validators,
        } => {
            aggregate_decryption_cmd(&client, auction_id, round, &validators).await?;
        }

        Commands::Settle {
            sender,
            auction_id,
            winner,
            winning_price,
            winner_index,
            num_valid_bids,
        } => {
            settle_cmd(
                &client,
                &sender,
                auction_id,
                &winner,
                winning_price,
                winner_index,
                num_valid_bids,
            )
            .await?;
        }
    }

    Ok(())
}
