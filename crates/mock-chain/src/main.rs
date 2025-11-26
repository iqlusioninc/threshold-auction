//! Mock chain server for local testing of the threshold auction system.
//!
//! This provides a JSON-RPC server that simulates on-chain state management
//! for the auction module without requiring a real blockchain.

use anyhow::Result;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use auction_module::{handlers, AuctionState as ModuleState, CallContext};
use auction_types::{
    AuctionState, AuctionType, G1Point, G2Point, MasterPublicKey, PartialDecryptionShare,
    PedersenCommitment, ThresholdCiphertext,
};

mod types;
use types::*;

/// Shared chain state.
struct ChainState {
    /// Module state
    module: ModuleState,
    /// Current block height (simulated)
    block_height: u64,
    /// Current timestamp (simulated, can be advanced)
    timestamp: u64,
}

impl ChainState {
    fn new() -> Self {
        Self {
            module: ModuleState::new(),
            block_height: 0,
            timestamp: 0,
        }
    }

    fn advance_block(&mut self) {
        self.block_height += 1;
        self.timestamp += 12; // ~12 second blocks
    }

    fn set_timestamp(&mut self, ts: u64) {
        self.timestamp = ts;
    }
}

/// RPC API definition for the mock chain.
#[rpc(server)]
pub trait MockChainApi {
    // ============ Admin Methods ============

    /// Initialize the chain with genesis config.
    #[method(name = "admin_init")]
    async fn admin_init(&self, config: GenesisConfigRpc) -> Result<bool, ErrorObjectOwned>;

    /// Advance the chain by one block.
    #[method(name = "admin_advanceBlock")]
    async fn admin_advance_block(&self) -> Result<BlockInfo, ErrorObjectOwned>;

    /// Set the current timestamp (for testing time-dependent logic).
    #[method(name = "admin_setTimestamp")]
    async fn admin_set_timestamp(&self, timestamp: u64) -> Result<bool, ErrorObjectOwned>;

    /// Set master public key and validator keys.
    #[method(name = "admin_setMasterKey")]
    async fn admin_set_master_key(
        &self,
        mpk: MasterPublicKeyRpc,
        validator_keys: Vec<ValidatorKeyRpc>,
    ) -> Result<bool, ErrorObjectOwned>;

    // ============ Auction Methods ============

    /// Create a new auction.
    #[method(name = "auction_create")]
    async fn auction_create(&self, params: CreateAuctionParams) -> Result<u64, ErrorObjectOwned>;

    /// Submit an encrypted bid.
    #[method(name = "auction_submitBid")]
    async fn auction_submit_bid(&self, params: SubmitBidParams) -> Result<bool, ErrorObjectOwned>;

    /// Submit a partial decryption share.
    #[method(name = "auction_submitPartialDecryption")]
    async fn auction_submit_partial_decryption(
        &self,
        params: SubmitPartialDecryptionParams,
    ) -> Result<bool, ErrorObjectOwned>;

    /// Aggregate decryption shares into a key.
    #[method(name = "auction_aggregateDecryptionKey")]
    async fn auction_aggregate_decryption_key(
        &self,
        auction_id: u64,
        round: u64,
        validator_indices: Vec<u32>,
    ) -> Result<DecryptionKeyRpc, ErrorObjectOwned>;

    /// Settle an auction with proof.
    #[method(name = "auction_settle")]
    async fn auction_settle(
        &self,
        params: SettleAuctionParams,
    ) -> Result<AuctionResultRpc, ErrorObjectOwned>;

    /// Claim refund for a non-winning bid.
    #[method(name = "auction_claimRefund")]
    async fn auction_claim_refund(
        &self,
        sender: String,
        auction_id: u64,
    ) -> Result<u64, ErrorObjectOwned>;

    // ============ Query Methods ============

    /// Get current block info.
    #[method(name = "chain_getBlockInfo")]
    async fn chain_get_block_info(&self) -> Result<BlockInfo, ErrorObjectOwned>;

    /// Get auction by ID.
    #[method(name = "query_getAuction")]
    async fn query_get_auction(
        &self,
        auction_id: u64,
    ) -> Result<Option<AuctionConfigRpc>, ErrorObjectOwned>;

    /// Get all bids for an auction.
    #[method(name = "query_getAuctionBids")]
    async fn query_get_auction_bids(
        &self,
        auction_id: u64,
    ) -> Result<Vec<EncryptedBidRpc>, ErrorObjectOwned>;

    /// Get decryption key for an auction.
    #[method(name = "query_getDecryptionKey")]
    async fn query_get_decryption_key(
        &self,
        auction_id: u64,
        round: u64,
    ) -> Result<Option<DecryptionKeyRpc>, ErrorObjectOwned>;

    /// Get auction result.
    #[method(name = "query_getAuctionResult")]
    async fn query_get_auction_result(
        &self,
        auction_id: u64,
    ) -> Result<Option<AuctionResultRpc>, ErrorObjectOwned>;

    /// Get master public key.
    #[method(name = "query_getMasterPublicKey")]
    async fn query_get_master_public_key(
        &self,
    ) -> Result<Option<MasterPublicKeyRpc>, ErrorObjectOwned>;

    /// List all auctions.
    #[method(name = "query_listAuctions")]
    async fn query_list_auctions(&self) -> Result<Vec<AuctionConfigRpc>, ErrorObjectOwned>;

    /// Get auctions ready for settlement (decrypted but not settled).
    #[method(name = "query_getSettleableAuctions")]
    async fn query_get_settleable_auctions(&self) -> Result<Vec<u64>, ErrorObjectOwned>;
}

/// Implementation of the mock chain RPC server.
struct MockChainServer {
    state: Arc<RwLock<ChainState>>,
}

impl MockChainServer {
    fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ChainState::new())),
        }
    }

    fn make_context(&self, sender: &str) -> CallContext {
        let state = self.state.read();
        CallContext {
            sender: parse_address(sender),
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: 0,
        }
    }

    fn rpc_error(msg: &str) -> ErrorObjectOwned {
        ErrorObjectOwned::owned(-32000, msg.to_string(), None::<()>)
    }
}

#[async_trait]
impl MockChainApiServer for MockChainServer {
    async fn admin_init(&self, config: GenesisConfigRpc) -> Result<bool, ErrorObjectOwned> {
        let mut state = self.state.write();

        // Set threshold config
        if let (Some(t), Some(n)) = (config.threshold_t, config.threshold_n) {
            // Threshold is stored in the master public key
        }

        // Set initial timestamp
        if let Some(ts) = config.initial_timestamp {
            state.timestamp = ts;
        }

        info!("Chain initialized");
        Ok(true)
    }

    async fn admin_advance_block(&self) -> Result<BlockInfo, ErrorObjectOwned> {
        let mut state = self.state.write();
        state.advance_block();
        Ok(BlockInfo {
            height: state.block_height,
            timestamp: state.timestamp,
        })
    }

    async fn admin_set_timestamp(&self, timestamp: u64) -> Result<bool, ErrorObjectOwned> {
        let mut state = self.state.write();
        state.set_timestamp(timestamp);
        info!("Timestamp set to {}", timestamp);
        Ok(true)
    }

    async fn admin_set_master_key(
        &self,
        mpk: MasterPublicKeyRpc,
        validator_keys: Vec<ValidatorKeyRpc>,
    ) -> Result<bool, ErrorObjectOwned> {
        let mut state = self.state.write();

        let master_pk = MasterPublicKey {
            mpk: G2Point(
                hex::decode(&mpk.mpk)
                    .map_err(|e| Self::rpc_error(&format!("Invalid mpk hex: {}", e)))?
                    .try_into()
                    .map_err(|_| Self::rpc_error("MPK must be 96 bytes"))?,
            ),
            threshold: mpk.threshold,
            total_validators: mpk.total_validators,
        };

        let keys: Vec<(u32, G1Point)> = validator_keys
            .into_iter()
            .map(|k| {
                let pk_bytes: [u8; 48] = hex::decode(&k.public_key)
                    .unwrap_or_default()
                    .try_into()
                    .unwrap_or([0u8; 48]);
                (k.index, G1Point(pk_bytes))
            })
            .collect();

        let ctx = CallContext {
            sender: [0u8; 32],
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: 0,
        };

        handlers::handle_set_master_public_key(&mut state.module, &ctx, master_pk, keys)
            .map_err(|e| Self::rpc_error(&format!("Failed to set master key: {}", e)))?;

        info!("Master public key set");
        Ok(true)
    }

    async fn auction_create(&self, params: CreateAuctionParams) -> Result<u64, ErrorObjectOwned> {
        let mut state = self.state.write();
        let ctx = CallContext {
            sender: parse_address(&params.sender),
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: 0,
        };

        let auction_type = match params.auction_type.as_str() {
            "first_price" => AuctionType::FirstPrice,
            "second_price" => AuctionType::SecondPrice,
            "gsp" => AuctionType::GeneralizedSecondPrice {
                quality_scores: params
                    .quality_scores
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(addr, score)| (parse_address(&addr), score))
                    .collect(),
            },
            _ => return Err(Self::rpc_error("Invalid auction type")),
        };

        let auction_id = handlers::handle_create_auction(
            &mut state.module,
            &ctx,
            auction_type,
            params.start_time,
            params.end_time,
            params.decryption_round,
            params.settlement_deadline,
            params.min_bid,
            params.reserve_price,
            auction_types::AuctionMetadata::default(),
        )
        .map_err(|e| Self::rpc_error(&format!("Failed to create auction: {}", e)))?;

        info!("Created auction {}", auction_id);
        Ok(auction_id)
    }

    async fn auction_submit_bid(&self, params: SubmitBidParams) -> Result<bool, ErrorObjectOwned> {
        let mut state = self.state.write();
        let ctx = CallContext {
            sender: parse_address(&params.sender),
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: params.deposit,
        };

        let commitment = PedersenCommitment {
            point: G1Point(
                hex::decode(&params.commitment)
                    .map_err(|e| Self::rpc_error(&format!("Invalid commitment: {}", e)))?
                    .try_into()
                    .map_err(|_| Self::rpc_error("Commitment must be 48 bytes"))?,
            ),
        };

        let ciphertext = ThresholdCiphertext {
            ephemeral_pubkey: G2Point(
                hex::decode(&params.ciphertext.ephemeral_pubkey)
                    .map_err(|e| Self::rpc_error(&format!("Invalid ephemeral pubkey: {}", e)))?
                    .try_into()
                    .map_err(|_| Self::rpc_error("Ephemeral pubkey must be 96 bytes"))?,
            ),
            ciphertext: hex::decode(&params.ciphertext.ciphertext)
                .map_err(|e| Self::rpc_error(&format!("Invalid ciphertext: {}", e)))?,
            tag: hex::decode(&params.ciphertext.tag)
                .map_err(|e| Self::rpc_error(&format!("Invalid tag: {}", e)))?
                .try_into()
                .map_err(|_| Self::rpc_error("Tag must be 16 bytes"))?,
            nonce: hex::decode(&params.ciphertext.nonce)
                .map_err(|e| Self::rpc_error(&format!("Invalid nonce: {}", e)))?
                .try_into()
                .map_err(|_| Self::rpc_error("Nonce must be 12 bytes"))?,
        };

        handlers::handle_submit_bid(
            &mut state.module,
            &ctx,
            params.auction_id,
            commitment,
            ciphertext,
            params.deposit,
        )
        .map_err(|e| Self::rpc_error(&format!("Failed to submit bid: {}", e)))?;

        info!(
            "Bid submitted for auction {} by {}",
            params.auction_id, params.sender
        );
        Ok(true)
    }

    async fn auction_submit_partial_decryption(
        &self,
        params: SubmitPartialDecryptionParams,
    ) -> Result<bool, ErrorObjectOwned> {
        let mut state = self.state.write();
        let ctx = CallContext {
            sender: [0u8; 32],
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: 0,
        };

        let partial = PartialDecryptionShare {
            validator_index: params.validator_index,
            partial_sig: G1Point(
                hex::decode(&params.partial_sig)
                    .map_err(|e| Self::rpc_error(&format!("Invalid partial sig: {}", e)))?
                    .try_into()
                    .map_err(|_| Self::rpc_error("Partial sig must be 48 bytes"))?,
            ),
            proof: auction_types::DiscreteLogProof {
                challenge: auction_types::Scalar(
                    hex::decode(&params.proof_challenge)
                        .map_err(|e| Self::rpc_error(&format!("Invalid challenge: {}", e)))?
                        .try_into()
                        .map_err(|_| Self::rpc_error("Challenge must be 32 bytes"))?,
                ),
                response: auction_types::Scalar(
                    hex::decode(&params.proof_response)
                        .map_err(|e| Self::rpc_error(&format!("Invalid response: {}", e)))?
                        .try_into()
                        .map_err(|_| Self::rpc_error("Response must be 32 bytes"))?,
                ),
            },
        };

        handlers::handle_submit_partial_decryption(
            &mut state.module,
            &ctx,
            params.auction_id,
            params.round,
            partial,
        )
        .map_err(|e| Self::rpc_error(&format!("Failed to submit partial decryption: {}", e)))?;

        info!(
            "Partial decryption submitted for auction {} from validator {}",
            params.auction_id, params.validator_index
        );
        Ok(true)
    }

    async fn auction_aggregate_decryption_key(
        &self,
        auction_id: u64,
        round: u64,
        validator_indices: Vec<u32>,
    ) -> Result<DecryptionKeyRpc, ErrorObjectOwned> {
        let mut state = self.state.write();
        let ctx = CallContext {
            sender: [0u8; 32],
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: 0,
        };

        let key = handlers::handle_aggregate_decryption_key(
            &mut state.module,
            &ctx,
            auction_id,
            round,
            validator_indices,
        )
        .map_err(|e| Self::rpc_error(&format!("Failed to aggregate key: {}", e)))?;

        info!("Decryption key aggregated for auction {}", auction_id);
        Ok(DecryptionKeyRpc {
            sigma: hex::encode(key.sigma.0),
            round: key.round,
        })
    }

    async fn auction_settle(
        &self,
        params: SettleAuctionParams,
    ) -> Result<AuctionResultRpc, ErrorObjectOwned> {
        let mut state = self.state.write();
        let ctx = CallContext {
            sender: parse_address(&params.sender),
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: 0,
        };

        let proof = auction_types::SP1AuctionProof {
            proof_bytes: hex::decode(&params.proof_bytes).unwrap_or_default(),
            public_values: auction_types::AuctionPublicValues {
                auction_id: params.auction_id,
                commitments_hash: hex::decode(&params.commitments_hash)
                    .unwrap_or_default()
                    .try_into()
                    .unwrap_or([0u8; 32]),
                winner_index: params.winner_index,
                winning_price: params.winning_price,
                num_valid_bids: params.num_valid_bids,
            },
            vkey_hash: [0u8; 32], // Mock doesn't verify vkey
        };

        let result = handlers::handle_settle_auction(
            &mut state.module,
            &ctx,
            params.auction_id,
            parse_address(&params.winner),
            params.winning_price,
            proof,
        )
        .map_err(|e| Self::rpc_error(&format!("Failed to settle: {}", e)))?;

        info!(
            "Auction {} settled. Winner: {}, Price: {}",
            params.auction_id, params.winner, params.winning_price
        );
        Ok(AuctionResultRpc::from(result))
    }

    async fn auction_claim_refund(
        &self,
        sender: String,
        auction_id: u64,
    ) -> Result<u64, ErrorObjectOwned> {
        let mut state = self.state.write();
        let ctx = CallContext {
            sender: parse_address(&sender),
            block_height: state.block_height,
            timestamp: state.timestamp,
            value: 0,
        };

        let refund = handlers::handle_claim_refund(&mut state.module, &ctx, auction_id)
            .map_err(|e| Self::rpc_error(&format!("Failed to claim refund: {}", e)))?;

        info!("Refund of {} claimed by {}", refund, sender);
        Ok(refund)
    }

    async fn chain_get_block_info(&self) -> Result<BlockInfo, ErrorObjectOwned> {
        let state = self.state.read();
        Ok(BlockInfo {
            height: state.block_height,
            timestamp: state.timestamp,
        })
    }

    async fn query_get_auction(
        &self,
        auction_id: u64,
    ) -> Result<Option<AuctionConfigRpc>, ErrorObjectOwned> {
        let state = self.state.read();
        Ok(state.module.get_auction(auction_id).map(AuctionConfigRpc::from))
    }

    async fn query_get_auction_bids(
        &self,
        auction_id: u64,
    ) -> Result<Vec<EncryptedBidRpc>, ErrorObjectOwned> {
        let state = self.state.read();
        let bids = state.module.get_auction_bids(auction_id);
        Ok(bids.into_iter().map(EncryptedBidRpc::from).collect())
    }

    async fn query_get_decryption_key(
        &self,
        auction_id: u64,
        round: u64,
    ) -> Result<Option<DecryptionKeyRpc>, ErrorObjectOwned> {
        let state = self.state.read();
        Ok(state
            .module
            .decryption_keys
            .get(&(auction_id, round))
            .map(|k| DecryptionKeyRpc {
                sigma: hex::encode(k.sigma.0),
                round: k.round,
            }))
    }

    async fn query_get_auction_result(
        &self,
        auction_id: u64,
    ) -> Result<Option<AuctionResultRpc>, ErrorObjectOwned> {
        let state = self.state.read();
        Ok(state.module.results.get(&auction_id).cloned().map(AuctionResultRpc::from))
    }

    async fn query_get_master_public_key(
        &self,
    ) -> Result<Option<MasterPublicKeyRpc>, ErrorObjectOwned> {
        let state = self.state.read();
        Ok(state.module.master_public_key.as_ref().map(|mpk| MasterPublicKeyRpc {
            mpk: hex::encode(mpk.mpk.0),
            threshold: mpk.threshold,
            total_validators: mpk.total_validators,
        }))
    }

    async fn query_list_auctions(&self) -> Result<Vec<AuctionConfigRpc>, ErrorObjectOwned> {
        let state = self.state.read();
        Ok(state
            .module
            .auctions
            .values()
            .map(AuctionConfigRpc::from)
            .collect())
    }

    async fn query_get_settleable_auctions(&self) -> Result<Vec<u64>, ErrorObjectOwned> {
        let state = self.state.read();
        Ok(state
            .module
            .auctions
            .iter()
            .filter(|(_, a)| a.state == AuctionState::Decrypted)
            .map(|(id, _)| *id)
            .collect())
    }
}

fn parse_address(s: &str) -> [u8; 32] {
    let mut addr = [0u8; 32];
    if let Ok(bytes) = hex::decode(s.trim_start_matches("0x")) {
        let len = bytes.len().min(32);
        addr[..len].copy_from_slice(&bytes[..len]);
    }
    addr
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mock_chain=info".parse().unwrap())
                .add_directive("jsonrpsee=warn".parse().unwrap()),
        )
        .init();

    let addr: SocketAddr = "127.0.0.1:9944".parse()?;

    info!("Starting mock chain server on {}", addr);

    let server = Server::builder().build(addr).await?;
    let handle = server.start(MockChainServer::new().into_rpc());

    info!("Mock chain server running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    handle.stop()?;
    handle.stopped().await;

    Ok(())
}
