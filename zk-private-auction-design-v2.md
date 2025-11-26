# ZK-Proven Private Auction System on Sovereign SDK

## Design Document for Implementation

**Version:** 2.0  
**Date:** November 2025  
**Target Framework:** Sovereign SDK (Rust)  
**Encryption:** Commonware Threshold BLS (Battleware)  
**zkVM:** SP1 (Succinct)  
**Primary Use Case:** Decentralized Ad Auction (Google Ads-like)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Threshold Encryption Design](#3-threshold-encryption-design)
4. [Protocol Flow](#4-protocol-flow)
5. [Data Structures](#5-data-structures)
6. [Module Implementation](#6-module-implementation)
7. [SP1 Circuit Specification](#7-sp1-circuit-specification)
8. [Threshold Decryption Service](#8-threshold-decryption-service)
9. [Client SDK](#9-client-sdk)
10. [Cryptographic Primitives](#10-cryptographic-primitives)
11. [Testing Strategy](#11-testing-strategy)
12. [Deployment Guide](#12-deployment-guide)
13. [Security Considerations](#13-security-considerations)

---

## 1. Executive Summary

### 1.1 Problem Statement

Traditional on-chain auctions expose bid values publicly, enabling:
- Front-running by miners/sequencers
- Strategic underbidding by competitors who can see others' bids
- Information leakage about advertiser budgets and strategies

Previous designs relied on a trusted sequencer for bid privacy. This creates a single point of trust failure.

### 1.2 Solution Overview

We implement a **threshold-encrypted auction** with ZK settlement:

1. **Timelock Encryption**: Bidders encrypt bids to a future round number using threshold BLS IBE
2. **Commitment Phase**: Encrypted bids + Pedersen commitments submitted on-chain
3. **Decryption Phase**: Validators produce threshold signature at round N, enabling decryption
4. **Settlement Phase**: Any party can decrypt, run auction in SP1 zkVM, and submit proof

**Key Innovation**: No single party ever sees bid values before the designated time. Privacy is distributed across the validator committee (t-of-n threshold).

### 1.3 Key Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Bid Privacy** | No single party can decrypt early | Threshold BLS (t-of-n) |
| **Timelock** | Bids unlock at predetermined round | IBE with round number as identity |
| **Verifiable Correctness** | Auction rules provably followed | SP1 ZK proof verified on-chain |
| **Permissionless Settlement** | Anyone can settle with proof | No trusted sequencer required |
| **MEV Resistance** | Validators cannot see bids when ordering | Ciphertexts committed before decryption |

### 1.4 Trust Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TRUST MODEL v2.0                                │
├─────────────────────────────────────────────────────────────────────────┤
│  Privacy:    Threshold trust (t-of-n validators must collude)          │
│              Default: 2/3 threshold matches BFT consensus              │
├─────────────────────────────────────────────────────────────────────────┤
│  Timing:     Decryption key released at round N automatically          │
│              Validators CANNOT withhold (liveness from consensus)      │
├─────────────────────────────────────────────────────────────────────────┤
│  Integrity:  NOT trusted - SP1 ZK proof guarantees correctness         │
│              Anyone can verify, anyone can generate proof              │
├─────────────────────────────────────────────────────────────────────────┤
│  Ordering:   Ciphertexts finalized in block before decryption round    │
│              No party knows bid values when ordering commitments       │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.5 Comparison: v1 (Sequencer) vs v2 (Threshold)

| Aspect | v1: Trusted Sequencer | v2: Threshold Encryption |
|--------|----------------------|--------------------------|
| Privacy trust | Single sequencer | t-of-n validators |
| Settlement | Sequencer only | Permissionless |
| Key management | Sequencer holds key | Distributed key shares |
| Collusion resistance | 1 party | t parties |
| Liveness | Sequencer must be online | Tied to consensus |
| Complexity | Lower | Higher |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           BIDDER CLIENTS                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      │
│  │  Advertiser │  │  Advertiser │  │  Advertiser │                      │
│  │      A      │  │      B      │  │      C      │                      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                      │
│         │                │                │                             │
│    [Threshold       [Threshold       [Threshold                         │
│     Encrypted]       Encrypted]       Encrypted]                        │
│    [+ Pedersen      [+ Pedersen      [+ Pedersen                        │
│     Commitment]      Commitment]      Commitment]                       │
└─────────┼────────────────┼────────────────┼─────────────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SOVEREIGN SDK ROLLUP                               │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    AUCTION MODULE (on-chain)                     │   │
│  │  • Stores encrypted bids + Pedersen commitments                 │   │
│  │  • Tracks decryption round for each auction                     │   │
│  │  • Verifies SP1 proofs of auction correctness                   │   │
│  │  • Executes settlements and token transfers                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ▲                                          │
│                              │                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │              THRESHOLD DECRYPTION COMMITTEE                      │   │
│  │                   (Validator Set)                                │   │
│  │                                                                  │   │
│  │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐                    │   │
│  │  │ V1  │  │ V2  │  │ V3  │  │ V4  │  │ ... │                    │   │
│  │  │sk_1 │  │sk_2 │  │sk_3 │  │sk_4 │  │sk_n │                    │   │
│  │  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘                    │   │
│  │     │        │        │        │        │                        │   │
│  │     └────────┴────────┼────────┴────────┘                        │   │
│  │                       │                                          │   │
│  │              Threshold Signature σ_round                         │   │
│  │              (produced at each round)                            │   │
│  └───────────────────────┼──────────────────────────────────────────┘   │
│                          │                                              │
│                          ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    SETTLEMENT SERVICE                            │   │
│  │                  (Permissionless - anyone can run)               │   │
│  │                                                                  │   │
│  │  1. Fetch encrypted bids from chain state                       │   │
│  │  2. Fetch threshold signature for decryption round              │   │
│  │  3. Decrypt all bids using σ_round as IBE decryption key        │   │
│  │  4. Run auction logic in SP1 zkVM                               │   │
│  │  5. Generate SP1 proof                                          │   │
│  │  6. Submit SettleAuction tx with proof                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    DATA AVAILABILITY LAYER                       │   │
│  │                    (Celestia / Avail / Ethereum)                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Overview

| Component | Language | Location | Responsibility |
|-----------|----------|----------|----------------|
| `auction-types` | Rust | `crates/types/` | Shared type definitions |
| `auction-module` | Rust | `crates/module/` | Sovereign SDK module (on-chain) |
| `auction-circuit` | Rust | `crates/circuit/` | SP1 program for zkVM |
| `auction-settler` | Rust | `crates/settler/` | Permissionless settlement service |
| `auction-client` | Rust | `crates/client/` | Bidder SDK library |
| `auction-crypto` | Rust | `crates/crypto/` | Threshold encryption primitives |
| `threshold-dkg` | Rust | `crates/dkg/` | Distributed key generation |

### 2.3 Crate Dependencies

```toml
# Cargo.toml (workspace)
[workspace]
resolver = "2"
members = [
    "crates/types",
    "crates/crypto",
    "crates/module",
    "crates/circuit",
    "crates/settler",
    "crates/client",
    "crates/dkg",
]

[workspace.dependencies]
# Sovereign SDK
sov-modules-api = "0.3"
sov-state = "0.3"
sov-bank = "0.3"

# BLS Cryptography (Commonware-compatible)
blst = "0.3"                    # BLS12-381 optimized implementation
bls12_381 = "0.8"               # Pure Rust fallback
group = "0.13"
ff = "0.13"
pairing = "0.23"

# Threshold Cryptography
threshold-bls = "0.1"           # Or implement based on Commonware
vsss-rs = "3.0"                 # Verifiable secret sharing

# General Crypto
rand = "0.8"
sha2 = "0.10"
hkdf = "0.12"

# Serialization
borsh = "1.0"
serde = { version = "1.0", features = ["derive"] }

# SP1 zkVM
sp1-sdk = "3.0"
sp1-zkvm = "3.0"
sp1-helper = "3.0"

# Async
tokio = { version = "1.0", features = ["full"] }
```

---

## 3. Threshold Encryption Design

### 3.1 Commonware Threshold BLS Overview

Commonware's Battleware implements **Identity-Based Encryption (IBE)** using threshold BLS signatures:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   THRESHOLD BLS IBE SCHEME                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  SETUP (DKG):                                                           │
│    • n validators run distributed key generation                        │
│    • Each validator i gets secret share sk_i                           │
│    • Public master key MPK published on-chain                          │
│    • Threshold t = 2n/3 + 1 (matches BFT assumption)                   │
│                                                                         │
│  ENCRYPTION (by bidder):                                                │
│    • Identity = auction_id || decryption_round                         │
│    • id_hash = hash_to_G1(identity)                                    │
│    • r ← random scalar                                                  │
│    • C1 = g2^r                           (ephemeral public key)        │
│    • shared = e(id_hash, MPK)^r          (pairing-based shared secret) │
│    • key = KDF(shared)                                                  │
│    • C2 = AES_key(plaintext)             (encrypted bid)               │
│    • Ciphertext = (C1, C2)                                             │
│                                                                         │
│  DECRYPTION KEY PRODUCTION (by validators at round N):                  │
│    • Each validator i computes: σ_i = sk_i · hash_to_G1(identity)      │
│    • Validators broadcast partial signatures                            │
│    • Anyone aggregates t signatures: σ = Σ λ_i · σ_i                   │
│    • σ is the decryption key for identity                              │
│                                                                         │
│  DECRYPTION (by anyone with σ):                                         │
│    • shared' = e(σ, C1)                                                │
│    • key = KDF(shared')                                                │
│    • plaintext = AES_key^{-1}(C2)                                      │
│                                                                         │
│  SECURITY:                                                              │
│    • < t validators cannot compute σ early                             │
│    • Once round N arrives, σ is produced automatically                 │
│    • Decryption is deterministic given σ                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Integration with Sovereign SDK Consensus

```
┌─────────────────────────────────────────────────────────────────────────┐
│              LEVERAGING EXISTING VALIDATOR INFRASTRUCTURE               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Option A: Separate Threshold Key (Recommended)                         │
│  ─────────────────────────────────────────────────────────────────────  │
│  • Run DKG specifically for auction encryption                          │
│  • Validators hold consensus key + auction decryption share            │
│  • Decryption signatures included in block production                   │
│  • Pro: Clean separation, can adjust threshold independently           │
│  • Con: Additional key ceremony required                                │
│                                                                         │
│  Option B: Derive from Consensus Signatures                             │
│  ─────────────────────────────────────────────────────────────────────  │
│  • Use block signature as pseudo-random beacon                          │
│  • Decrypt when block at height H is finalized                          │
│  • Pro: No additional infrastructure                                    │
│  • Con: Less flexible, ties to block production                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Identity Derivation

The "identity" in IBE determines when decryption becomes possible:

```rust
/// Compute the IBE identity for an auction's decryption round
pub fn compute_auction_identity(auction_id: u64, decryption_round: u64) -> Vec<u8> {
    let mut identity = Vec::with_capacity(32);
    identity.extend_from_slice(b"AUCTION_DECRYPT_V1:");
    identity.extend_from_slice(&auction_id.to_le_bytes());
    identity.extend_from_slice(b":");
    identity.extend_from_slice(&decryption_round.to_le_bytes());
    identity
}
```

### 3.4 Batched Threshold Decryption

For efficiency with many bids, use batch decryption (from USENIX Security 2024):

```
Standard: O(n × B) communication for n validators, B bids
Batched:  O(n + B) communication

How it works:
1. All bids encrypted to same identity (auction_id, round)
2. Validators produce ONE partial signature per identity
3. Aggregate signature works for ALL bids with that identity
4. Each bid decrypted locally with shared aggregate signature
```

---

## 4. Protocol Flow

### 4.1 Auction Lifecycle State Machine

```
                    ┌──────────────┐
                    │   CREATED    │
                    │  (pending)   │
                    └──────┬───────┘
                           │ start_time reached
                           ▼
                    ┌──────────────┐
        ┌──────────│    OPEN      │◄─────────┐
        │          │  (accepting) │          │
        │          └──────┬───────┘          │
        │                 │ end_time reached │
        │                 ▼                  │
        │          ┌──────────────┐          │
        │          │   SEALED     │          │
        │          │  (waiting)   │          │
        │          └──────┬───────┘          │
        │                 │ decryption_round │
        │                 │ reached          │
        │                 ▼                  │
        │          ┌──────────────┐          │
        │          │  DECRYPTED   │          │
        │          │  (proving)   │          │
        │          └──────┬───────┘          │
        │                 │ proof submitted  │
        │                 ▼                  │
        │          ┌──────────────┐          │
  timeout          │   SETTLED    │          │
  (no bids)        │  (complete)  │          │
        │          └──────────────┘          │
        │                                    │
        └────────────────────────────────────┘
                     (cancelled)
```

### 4.2 Detailed Protocol Steps

```
════════════════════════════════════════════════════════════════════════════
PHASE 0: SYSTEM SETUP (One-time)
════════════════════════════════════════════════════════════════════════════

Validators run Distributed Key Generation (DKG):
    1. Each validator i generates secret share contribution
    2. Validators exchange commitments (Feldman VSS)
    3. Validators exchange encrypted shares
    4. Each validator i derives final share sk_i
    5. Master public key MPK = Σ commitment_i published on-chain

On-chain state after DKG:
    master_public_key: G2Point,           // MPK for encryption
    threshold: u32,                        // t required for decryption
    validator_pubkeys: Vec<G1Point>,       // For share verification

════════════════════════════════════════════════════════════════════════════
PHASE 1: AUCTION CREATION
════════════════════════════════════════════════════════════════════════════

Publisher/Platform submits:
    CreateAuction {
        auction_type: AuctionType,
        start_time: u64,
        end_time: u64,
        decryption_round: u64,            // When bids can be decrypted
        settlement_deadline: u64,          // Must settle by this time
        min_bid: u64,
        reserve_price: Option<u64>,
        ad_slot_metadata: AdSlotInfo,
    }

Validation:
    - decryption_round > current_round
    - decryption_round corresponds to time after end_time
    - settlement_deadline > decryption_round + buffer

On-chain effects:
    - Auction config stored with derived identity
    - identity = hash(auction_id || decryption_round)

════════════════════════════════════════════════════════════════════════════
PHASE 2: BID SUBMISSION (before end_time)
════════════════════════════════════════════════════════════════════════════

Bidder computes locally:
    // 1. Create Pedersen commitment (for ZK binding)
    randomness = random_scalar()
    commitment = pedersen_commit(bid_value, randomness)
    
    // 2. Encrypt bid using threshold IBE
    identity = compute_auction_identity(auction_id, decryption_round)
    plaintext = serialize(bid_value, randomness)
    ciphertext = threshold_ibe_encrypt(MPK, identity, plaintext)

Bidder submits:
    SubmitBid {
        auction_id: u64,
        commitment: PedersenCommitment,    // For ZK proof binding
        ciphertext: ThresholdCiphertext,   // Encrypted (value, randomness)
        deposit: u64,
    }

On-chain effects:
    - Both commitment AND ciphertext stored
    - Deposit transferred to escrow
    - Bidder added to auction_bidders[auction_id]
    - BidSubmitted event (contains commitment + ciphertext, NOT value)

IMPORTANT: Ciphertext size is ~144 bytes (96 byte G2 point + 48 byte encrypted payload)

════════════════════════════════════════════════════════════════════════════
PHASE 3: SEALING (end_time to decryption_round)
════════════════════════════════════════════════════════════════════════════

During this period:
    - No more bids accepted
    - Ciphertexts are finalized on-chain
    - Validators continue producing blocks normally
    - NO ONE can decrypt bids yet (threshold not met)

Purpose:
    - Ensures ordering is committed before anyone knows bid values
    - Prevents MEV/front-running

════════════════════════════════════════════════════════════════════════════
PHASE 4: DECRYPTION KEY RELEASE (at decryption_round)
════════════════════════════════════════════════════════════════════════════

At round R = decryption_round:

    // Validators automatically produce partial signatures
    for each validator i in active_set:
        identity = compute_auction_identity(auction_id, R)
        id_point = hash_to_g1(identity)
        partial_sig_i = sk_i * id_point
        
        // Include in block or separate decryption beacon
        broadcast(PartialDecryptionKey {
            auction_id,
            round: R,
            validator_index: i,
            partial_sig: partial_sig_i,
            proof: prove_correct_share(partial_sig_i),
        })

Anyone can aggregate (once t partials available):
    decryption_key = aggregate_threshold_sigs(
        partial_sigs[0..t],
        validator_indices[0..t],
    )

On-chain event:
    DecryptionKeyReleased {
        auction_id,
        round: R,
        decryption_key: G1Point,
    }

════════════════════════════════════════════════════════════════════════════
PHASE 5: SETTLEMENT (permissionless, after decryption_round)
════════════════════════════════════════════════════════════════════════════

ANY party can settle by:

1. Fetch from chain:
    - Auction config
    - All bid ciphertexts
    - All Pedersen commitments
    - Decryption key (σ)

2. Decrypt all bids locally:
    for each (ciphertext, commitment) in bids:
        (bid_value, randomness) = threshold_ibe_decrypt(ciphertext, σ)
        
        // Verify commitment matches
        assert pedersen_commit(bid_value, randomness) == commitment

3. Run auction in SP1 zkVM:
    - Input: commitments, decrypted values, auction rules
    - Prove: winner has highest bid, price computed correctly
    - Output: (winner_index, winning_price)

4. Submit settlement:
    SettleAuction {
        auction_id,
        winner: Address,
        winning_price: u64,
        sp1_proof: SP1ProofWithPublicValues,
    }

On-chain verification:
    1. Verify SP1 proof using on-chain verifier
    2. Check public inputs match stored commitments
    3. Execute fund transfers

════════════════════════════════════════════════════════════════════════════
PHASE 6: REFUNDS
════════════════════════════════════════════════════════════════════════════

After settlement:
    - Winner: (deposit - winning_price) returned
    - Losers: Full deposit returned
    - Non-revealed (if ciphertext invalid): Deposit slashed
```

### 4.3 Sequence Diagram

```
Bidder A    Bidder B    Rollup    Validators(1..n)    Settler    SP1
   │           │          │              │              │         │
   │           │          │              │              │         │
   │  ════ SETUP (once) ════             │              │         │
   │           │          │◄────DKG──────│              │         │
   │           │          │──MPK on-chain│              │         │
   │           │          │              │              │         │
   │  ════ BIDDING PHASE ════            │              │         │
   │──Encrypt(bid_A)─────>│              │              │         │
   │──Commit(bid_A)──────>│              │              │         │
   │           │          │              │              │         │
   │           │──Encrypt+│              │              │         │
   │           │  Commit──>│              │              │         │
   │           │          │              │              │         │
   │  ════ SEALED (waiting) ════         │              │         │
   │           │          │              │              │         │
   │  ════ DECRYPTION ROUND ════         │              │         │
   │           │          │◄──partial_σ──│              │         │
   │           │          │──aggregate σ─│              │         │
   │           │          │              │              │         │
   │  ════ SETTLEMENT ════│              │              │         │
   │           │          │◄─────────────│──fetch bids──│         │
   │           │          │─────bids+σ───│─────────────>│         │
   │           │          │              │              │         │
   │           │          │              │──decrypt─────│         │
   │           │          │              │──run auction─│────────>│
   │           │          │              │◄────proof────│─────────│
   │           │          │              │              │         │
   │           │          │◄──SettleAuction+proof───────│         │
   │           │          │              │              │         │
   │           │          │  verify()    │              │         │
   │           │          │  transfer()  │              │         │
   │           │          │              │              │         │
   │◄─────Refund──────────│              │              │         │
   │           │◄─Refund──│              │              │         │
```

---

## 5. Data Structures

### 5.1 Core Types

```rust
// ============================================================
// FILE: crates/types/src/lib.rs
// ============================================================

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

// =========================
// CRYPTOGRAPHIC PRIMITIVES
// =========================

/// Compressed G1 point on BLS12-381 (48 bytes)
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct G1Point(pub [u8; 48]);

/// Compressed G2 point on BLS12-381 (96 bytes)
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct G2Point(pub [u8; 96]);

/// Scalar field element (32 bytes, little-endian)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Scalar(pub [u8; 32]);

/// Pedersen commitment: C = g^value * h^randomness
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub point: G1Point,
}

// =========================
// THRESHOLD ENCRYPTION
// =========================

/// Threshold IBE ciphertext (Commonware-compatible)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ThresholdCiphertext {
    /// Ephemeral public key: U = r·G2
    pub ephemeral_pubkey: G2Point,
    
    /// Encrypted payload (bid_value || randomness || padding)
    /// Using AES-256-GCM with key derived from pairing
    pub ciphertext: Vec<u8>,  // 48 bytes typically
    
    /// Authentication tag
    pub tag: [u8; 16],
    
    /// Nonce for AEAD
    pub nonce: [u8; 12],
}

/// Partial decryption share from a validator
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct PartialDecryptionShare {
    pub validator_index: u32,
    pub partial_sig: G1Point,  // sk_i · H(identity)
    pub proof: DiscreteLogProof,  // Proves correctness
}

/// DLEQ proof for partial signature correctness
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DiscreteLogProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

/// Aggregated decryption key (threshold signature)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DecryptionKey {
    pub sigma: G1Point,  // Σ λ_i · partial_sig_i
    pub round: u64,
}

/// Master public key for threshold encryption
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MasterPublicKey {
    pub mpk: G2Point,
    pub threshold: u32,
    pub total_validators: u32,
}

// =========================
// AUCTION TYPES
// =========================

/// Types of auctions supported
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum AuctionType {
    /// Winner pays their bid
    FirstPrice,
    
    /// Winner pays second-highest bid
    SecondPrice,
    
    /// Google-style: rank by bid * quality_score
    GeneralizedSecondPrice {
        quality_scores: Vec<(Address, u32)>,
    },
}

/// Auction lifecycle state
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum AuctionState {
    Created,       // Before start_time
    Open,          // Accepting bids
    Sealed,        // Bids locked, waiting for decryption
    Decrypted,     // Decryption key available, awaiting settlement
    Settled,       // Auction complete
    Cancelled,     // No valid bids or timeout
}

/// Full auction configuration
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionConfig {
    pub auction_id: u64,
    pub creator: Address,
    pub auction_type: AuctionType,
    pub state: AuctionState,
    
    // Timing
    pub start_time: u64,
    pub end_time: u64,
    pub decryption_round: u64,
    pub settlement_deadline: u64,
    
    // Rules
    pub min_bid: u64,
    pub reserve_price: Option<u64>,
    
    // Derived
    pub identity: [u8; 32],  // hash(auction_id || decryption_round)
    
    // Metadata
    pub metadata: AuctionMetadata,
}

/// Optional metadata for ad auctions
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionMetadata {
    pub ad_slot_id: Option<String>,
    pub placement: Option<String>,
    pub targeting_hash: Option<[u8; 32]>,
}

/// A submitted encrypted bid (stored on-chain)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EncryptedBid {
    pub bidder: Address,
    pub commitment: PedersenCommitment,
    pub ciphertext: ThresholdCiphertext,
    pub deposit: u64,
    pub timestamp: u64,
}

/// Decrypted bid (used off-chain for proving)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DecryptedBid {
    pub bidder: Address,
    pub commitment: PedersenCommitment,
    pub bid_value: u64,
    pub randomness: Scalar,
    pub index: usize,
}

/// Auction settlement result
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionResult {
    pub auction_id: u64,
    pub winner: Address,
    pub winning_price: u64,
    pub num_valid_bids: u32,
    pub settlement_time: u64,
    pub proof_hash: [u8; 32],
    pub settler: Address,  // Who submitted the settlement
}

// =========================
// SP1 PROOF
// =========================

/// SP1 proof of auction correctness
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SP1AuctionProof {
    /// Serialized SP1 proof
    pub proof_bytes: Vec<u8>,
    
    /// Public values from the proof
    pub public_values: AuctionPublicValues,
    
    /// Verification key hash (for upgradability)
    pub vkey_hash: [u8; 32],
}

/// Public values output by SP1 circuit
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AuctionPublicValues {
    pub auction_id: u64,
    pub commitments_hash: [u8; 32],  // Hash of all commitments
    pub winner_index: u32,
    pub winning_price: u64,
    pub num_valid_bids: u32,
}

/// Generic address type (matches Sovereign SDK)
pub type Address = [u8; 32];
```

### 5.2 Circuit I/O Types

```rust
// ============================================================
// FILE: crates/types/src/circuit_io.rs
// ============================================================

/// Input to SP1 circuit (private to prover)
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SP1CircuitInput {
    /// Auction identifier
    pub auction_id: u64,
    
    /// Auction type (determines pricing rule)
    pub auction_type: AuctionTypeCompact,
    
    /// All Pedersen commitments (from chain)
    pub commitments: Vec<PedersenCommitment>,
    
    /// Decrypted bid values (from threshold decryption)
    pub bid_values: Vec<u64>,
    
    /// Randomness for each bid (from threshold decryption)
    pub randomness: Vec<[u8; 32]>,
    
    /// Quality scores for GSP auctions
    pub quality_scores: Vec<u32>,
}

/// Compact auction type for circuit
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum AuctionTypeCompact {
    FirstPrice,
    SecondPrice,
    GSP,
}

impl SP1CircuitInput {
    /// Hash all commitments for binding
    pub fn commitments_hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for c in &self.commitments {
            hasher.update(&c.point.0);
        }
        hasher.finalize().into()
    }
}
```

---

## 6. Module Implementation

### 6.1 Module Definition

```rust
// ============================================================
// FILE: crates/module/src/lib.rs
// ============================================================

use sov_modules_api::prelude::*;
use sov_modules_api::{Context, Module, ModuleInfo, StateMap, StateValue, WorkingSet};
use auction_types::*;

mod call;
mod genesis;
mod query;
mod threshold;

pub use call::AuctionCall;
pub use genesis::AuctionModuleConfig;

/// Auction module errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuctionError {
    #[error("Auction not found: {0}")]
    AuctionNotFound(u64),
    
    #[error("Invalid state. Expected: {expected:?}, Got: {got:?}")]
    InvalidState { expected: AuctionState, got: AuctionState },
    
    #[error("Bidding period ended")]
    BiddingEnded,
    
    #[error("Decryption round not reached")]
    DecryptionNotReady,
    
    #[error("Settlement deadline passed")]
    SettlementDeadlinePassed,
    
    #[error("Insufficient deposit: need {required}, got {got}")]
    InsufficientDeposit { required: u64, got: u64 },
    
    #[error("Already submitted bid")]
    AlreadyBid,
    
    #[error("Already settled")]
    AlreadySettled,
    
    #[error("Invalid SP1 proof")]
    InvalidProof,
    
    #[error("Public values mismatch")]
    PublicValuesMismatch,
    
    #[error("Decryption key not available")]
    DecryptionKeyNotAvailable,
    
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    
    #[error("Master public key not set")]
    MasterKeyNotSet,
}

/// The Auction Module with Threshold Encryption
#[derive(ModuleInfo)]
pub struct AuctionModule<C: Context> {
    #[address]
    pub address: C::Address,
    
    // === Auction State ===
    
    #[state]
    pub next_auction_id: StateValue<u64>,
    
    #[state]
    pub auctions: StateMap<u64, AuctionConfig>,
    
    #[state]
    pub bids: StateMap<(u64, [u8; 32]), EncryptedBid>,
    
    #[state]
    pub auction_bidders: StateMap<u64, Vec<Address>>,
    
    #[state]
    pub results: StateMap<u64, AuctionResult>,
    
    #[state]
    pub escrow: StateMap<[u8; 32], u64>,
    
    // === Threshold Encryption State ===
    
    /// Master public key for threshold IBE
    #[state]
    pub master_public_key: StateValue<MasterPublicKey>,
    
    /// Decryption keys released by validators
    /// Key: (auction_id, round) -> aggregated decryption key
    #[state]
    pub decryption_keys: StateMap<(u64, u64), DecryptionKey>,
    
    /// Partial decryption shares
    /// Key: (auction_id, round, validator_index)
    #[state]
    pub partial_shares: StateMap<(u64, u64, u32), PartialDecryptionShare>,
    
    /// Validator public keys for share verification
    #[state]
    pub validator_pubkeys: StateMap<u32, G1Point>,
    
    // === SP1 Verification ===
    
    /// SP1 verification key
    #[state]
    pub sp1_vkey: StateValue<Vec<u8>>,
    
    /// SP1 vkey hash for quick checking
    #[state]
    pub sp1_vkey_hash: StateValue<[u8; 32]>,
    
    // === Bank Integration ===
    
    #[module]
    pub bank: sov_bank::Bank<C>,
}
```

### 6.2 Call Messages

```rust
// ============================================================
// FILE: crates/module/src/call.rs
// ============================================================

use super::*;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum AuctionCall {
    // === Auction Lifecycle ===
    
    CreateAuction {
        auction_type: AuctionType,
        start_time: u64,
        end_time: u64,
        decryption_round: u64,
        settlement_deadline: u64,
        min_bid: u64,
        reserve_price: Option<u64>,
        metadata: AuctionMetadata,
    },
    
    SubmitBid {
        auction_id: u64,
        commitment: PedersenCommitment,
        ciphertext: ThresholdCiphertext,
        deposit: u64,
    },
    
    /// Permissionless settlement with SP1 proof
    SettleAuction {
        auction_id: u64,
        winner: Address,
        winning_price: u64,
        proof: SP1AuctionProof,
    },
    
    ClaimRefund {
        auction_id: u64,
    },
    
    // === Threshold Key Management ===
    
    /// Submit partial decryption share (validators only)
    SubmitPartialDecryption {
        auction_id: u64,
        round: u64,
        partial: PartialDecryptionShare,
    },
    
    /// Aggregate partial shares into decryption key (anyone)
    AggregateDecryptionKey {
        auction_id: u64,
        round: u64,
        validator_indices: Vec<u32>,
    },
    
    // === Admin ===
    
    /// Set master public key (governance/DKG)
    SetMasterPublicKey {
        mpk: MasterPublicKey,
        validator_pubkeys: Vec<(u32, G1Point)>,
    },
    
    /// Update SP1 verification key
    UpdateSP1VerificationKey {
        vkey: Vec<u8>,
    },
}

impl<C: Context> Module for AuctionModule<C> {
    type Context = C;
    type Config = AuctionModuleConfig;
    type CallMessage = AuctionCall;

    fn call(
        &self,
        msg: Self::CallMessage,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse, Error> {
        match msg {
            AuctionCall::CreateAuction { 
                auction_type, start_time, end_time, decryption_round,
                settlement_deadline, min_bid, reserve_price, metadata 
            } => {
                self.create_auction(
                    auction_type, start_time, end_time, decryption_round,
                    settlement_deadline, min_bid, reserve_price, metadata,
                    context, working_set
                )
            },
            
            AuctionCall::SubmitBid { auction_id, commitment, ciphertext, deposit } => {
                self.submit_bid(auction_id, commitment, ciphertext, deposit, context, working_set)
            },
            
            AuctionCall::SettleAuction { auction_id, winner, winning_price, proof } => {
                self.settle_auction(auction_id, winner, winning_price, proof, context, working_set)
            },
            
            AuctionCall::ClaimRefund { auction_id } => {
                self.claim_refund(auction_id, context, working_set)
            },
            
            AuctionCall::SubmitPartialDecryption { auction_id, round, partial } => {
                self.submit_partial_decryption(auction_id, round, partial, context, working_set)
            },
            
            AuctionCall::AggregateDecryptionKey { auction_id, round, validator_indices } => {
                self.aggregate_decryption_key(auction_id, round, validator_indices, context, working_set)
            },
            
            AuctionCall::SetMasterPublicKey { mpk, validator_pubkeys } => {
                self.set_master_public_key(mpk, validator_pubkeys, context, working_set)
            },
            
            AuctionCall::UpdateSP1VerificationKey { vkey } => {
                self.update_sp1_vkey(vkey, context, working_set)
            },
        }
    }
}
```

### 6.3 Core Implementation

```rust
// ============================================================
// FILE: crates/module/src/impl.rs
// ============================================================

impl<C: Context> AuctionModule<C> {
    /// Create a new auction
    pub fn create_auction(
        &self,
        auction_type: AuctionType,
        start_time: u64,
        end_time: u64,
        decryption_round: u64,
        settlement_deadline: u64,
        min_bid: u64,
        reserve_price: Option<u64>,
        metadata: AuctionMetadata,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse, Error> {
        // Validate timing
        let now = context.block_timestamp();
        require!(start_time >= now, "Start time must be future");
        require!(end_time > start_time, "End must be after start");
        require!(decryption_round > 0, "Invalid decryption round");
        require!(settlement_deadline > decryption_round, "Settlement after decryption");
        
        // Check master key is set
        require!(
            self.master_public_key.get(working_set).is_some(),
            AuctionError::MasterKeyNotSet
        );
        
        let auction_id = self.next_auction_id.get(working_set).unwrap_or(1);
        self.next_auction_id.set(&(auction_id + 1), working_set);
        
        // Derive identity for threshold encryption
        let identity = compute_auction_identity(auction_id, decryption_round);
        
        let config = AuctionConfig {
            auction_id,
            creator: context.sender().to_bytes(),
            auction_type,
            state: AuctionState::Created,
            start_time,
            end_time,
            decryption_round,
            settlement_deadline,
            min_bid,
            reserve_price,
            identity,
            metadata,
        };
        
        self.auctions.set(&auction_id, &config, working_set);
        self.auction_bidders.set(&auction_id, &Vec::new(), working_set);
        
        Ok(CallResponse::default()
            .add_event("auction_created", &[
                ("auction_id", &auction_id.to_string()),
                ("decryption_round", &decryption_round.to_string()),
            ]))
    }
    
    /// Submit an encrypted bid
    pub fn submit_bid(
        &self,
        auction_id: u64,
        commitment: PedersenCommitment,
        ciphertext: ThresholdCiphertext,
        deposit: u64,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse, Error> {
        let mut config = self.auctions.get(&auction_id, working_set)
            .ok_or(AuctionError::AuctionNotFound(auction_id))?;
        
        let now = context.block_timestamp();
        
        // Update state if needed
        if now >= config.start_time && config.state == AuctionState::Created {
            config.state = AuctionState::Open;
        }
        
        require!(
            config.state == AuctionState::Open,
            AuctionError::InvalidState { 
                expected: AuctionState::Open, 
                got: config.state.clone() 
            }
        );
        require!(now < config.end_time, AuctionError::BiddingEnded);
        require!(deposit >= config.min_bid, AuctionError::InsufficientDeposit {
            required: config.min_bid,
            got: deposit,
        });
        
        // Validate ciphertext structure
        require!(
            ciphertext.ephemeral_pubkey.0.len() == 96,
            AuctionError::InvalidCiphertext
        );
        
        let bidder = context.sender().to_bytes();
        let key = (auction_id, bidder);
        
        require!(
            self.bids.get(&key, working_set).is_none(),
            AuctionError::AlreadyBid
        );
        
        // Transfer deposit to escrow
        let current_escrow = self.escrow.get(&bidder, working_set).unwrap_or(0);
        self.escrow.set(&bidder, &(current_escrow + deposit), working_set);
        
        // Store encrypted bid
        let bid = EncryptedBid {
            bidder,
            commitment,
            ciphertext,
            deposit,
            timestamp: now,
        };
        self.bids.set(&key, &bid, working_set);
        
        // Add to bidder list
        let mut bidders = self.auction_bidders.get(&auction_id, working_set)
            .unwrap_or_default();
        bidders.push(bidder);
        self.auction_bidders.set(&auction_id, &bidders, working_set);
        
        self.auctions.set(&auction_id, &config, working_set);
        
        Ok(CallResponse::default()
            .add_event("bid_submitted", &[
                ("auction_id", &auction_id.to_string()),
                ("bidder", &hex::encode(bidder)),
            ]))
    }
    
    /// Settle auction with SP1 proof (permissionless)
    pub fn settle_auction(
        &self,
        auction_id: u64,
        winner: Address,
        winning_price: u64,
        proof: SP1AuctionProof,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse, Error> {
        let mut config = self.auctions.get(&auction_id, working_set)
            .ok_or(AuctionError::AuctionNotFound(auction_id))?;
        
        let now = context.block_timestamp();
        
        // Update state transitions
        if now >= config.end_time && config.state == AuctionState::Open {
            config.state = AuctionState::Sealed;
        }
        
        // Check decryption key is available
        let dk_key = (auction_id, config.decryption_round);
        let _decryption_key = self.decryption_keys.get(&dk_key, working_set)
            .ok_or(AuctionError::DecryptionKeyNotAvailable)?;
        
        if config.state == AuctionState::Sealed {
            config.state = AuctionState::Decrypted;
        }
        
        require!(
            config.state == AuctionState::Decrypted,
            AuctionError::InvalidState {
                expected: AuctionState::Decrypted,
                got: config.state.clone(),
            }
        );
        
        require!(now <= config.settlement_deadline, AuctionError::SettlementDeadlinePassed);
        require!(
            self.results.get(&auction_id, working_set).is_none(),
            AuctionError::AlreadySettled
        );
        
        // Collect commitments for verification
        let bidders = self.auction_bidders.get(&auction_id, working_set)
            .unwrap_or_default();
        
        let commitments: Vec<PedersenCommitment> = bidders.iter()
            .filter_map(|b| self.bids.get(&(auction_id, *b), working_set))
            .map(|bid| bid.commitment)
            .collect();
        
        // Compute expected commitments hash
        let expected_commitments_hash = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            for c in &commitments {
                hasher.update(&c.point.0);
            }
            let result: [u8; 32] = hasher.finalize().into();
            result
        };
        
        // Verify public values match
        require!(
            proof.public_values.auction_id == auction_id,
            AuctionError::PublicValuesMismatch
        );
        require!(
            proof.public_values.commitments_hash == expected_commitments_hash,
            AuctionError::PublicValuesMismatch
        );
        require!(
            proof.public_values.winning_price == winning_price,
            AuctionError::PublicValuesMismatch
        );
        
        // Verify winner index maps to claimed winner
        let winner_index = proof.public_values.winner_index as usize;
        require!(
            winner_index < bidders.len() && bidders[winner_index] == winner,
            AuctionError::PublicValuesMismatch
        );
        
        // Verify SP1 proof
        let vkey = self.sp1_vkey.get(working_set)
            .ok_or(AuctionError::InvalidProof)?;
        let vkey_hash = self.sp1_vkey_hash.get(working_set)
            .ok_or(AuctionError::InvalidProof)?;
        
        require!(
            proof.vkey_hash == vkey_hash,
            AuctionError::InvalidProof
        );
        
        self.verify_sp1_proof(&proof, &vkey)?;
        
        // Execute settlement
        config.state = AuctionState::Settled;
        self.auctions.set(&auction_id, &config, working_set);
        
        // Deduct from winner's escrow
        let winner_escrow = self.escrow.get(&winner, working_set)
            .ok_or(AuctionError::InsufficientDeposit { required: winning_price, got: 0 })?;
        require!(
            winner_escrow >= winning_price,
            AuctionError::InsufficientDeposit { required: winning_price, got: winner_escrow }
        );
        self.escrow.set(&winner, &(winner_escrow - winning_price), working_set);
        
        // Store result
        let result = AuctionResult {
            auction_id,
            winner,
            winning_price,
            num_valid_bids: proof.public_values.num_valid_bids,
            settlement_time: now,
            proof_hash: sha256(&proof.proof_bytes),
            settler: context.sender().to_bytes(),
        };
        self.results.set(&auction_id, &result, working_set);
        
        Ok(CallResponse::default()
            .add_event("auction_settled", &[
                ("auction_id", &auction_id.to_string()),
                ("winner", &hex::encode(winner)),
                ("price", &winning_price.to_string()),
                ("settler", &hex::encode(context.sender())),
            ]))
    }
    
    /// Verify SP1 proof using on-chain verifier
    fn verify_sp1_proof(
        &self,
        proof: &SP1AuctionProof,
        vkey: &[u8],
    ) -> Result<(), Error> {
        // SP1 verification
        // In production, this would use sp1-verifier crate or precompile
        
        use sp1_verifier::Groth16Verifier;
        
        let public_values_bytes = borsh::to_vec(&proof.public_values)
            .map_err(|_| AuctionError::InvalidProof)?;
        
        Groth16Verifier::verify(
            &proof.proof_bytes,
            &public_values_bytes,
            vkey,
        ).map_err(|_| AuctionError::InvalidProof)?;
        
        Ok(())
    }
}

// Helper functions
fn compute_auction_identity(auction_id: u64, round: u64) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"AUCTION_IDENTITY_V1:");
    hasher.update(&auction_id.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.finalize().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    Sha256::digest(data).into()
}
```

### 6.4 Threshold Decryption Management

```rust
// ============================================================
// FILE: crates/module/src/threshold.rs
// ============================================================

impl<C: Context> AuctionModule<C> {
    /// Validator submits partial decryption share
    pub fn submit_partial_decryption(
        &self,
        auction_id: u64,
        round: u64,
        partial: PartialDecryptionShare,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse, Error> {
        // Verify auction exists and round matches
        let config = self.auctions.get(&auction_id, working_set)
            .ok_or(AuctionError::AuctionNotFound(auction_id))?;
        
        require!(
            round == config.decryption_round,
            "Round mismatch"
        );
        
        // Verify validator is authorized
        let validator_pubkey = self.validator_pubkeys.get(&partial.validator_index, working_set)
            .ok_or("Validator not registered")?;
        
        // Verify DLEQ proof that partial signature is correct
        self.verify_partial_signature_proof(
            &partial,
            &validator_pubkey,
            &config.identity,
        )?;
        
        // Store partial share
        let key = (auction_id, round, partial.validator_index);
        self.partial_shares.set(&key, &partial, working_set);
        
        Ok(CallResponse::default()
            .add_event("partial_decryption_submitted", &[
                ("auction_id", &auction_id.to_string()),
                ("validator", &partial.validator_index.to_string()),
            ]))
    }
    
    /// Aggregate partial shares into decryption key (anyone can call)
    pub fn aggregate_decryption_key(
        &self,
        auction_id: u64,
        round: u64,
        validator_indices: Vec<u32>,
        _context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse, Error> {
        let config = self.auctions.get(&auction_id, working_set)
            .ok_or(AuctionError::AuctionNotFound(auction_id))?;
        
        require!(round == config.decryption_round, "Round mismatch");
        
        let mpk = self.master_public_key.get(working_set)
            .ok_or(AuctionError::MasterKeyNotSet)?;
        
        require!(
            validator_indices.len() >= mpk.threshold as usize,
            "Insufficient shares"
        );
        
        // Collect partial signatures
        let mut partials = Vec::new();
        for idx in &validator_indices {
            let key = (auction_id, round, *idx);
            let partial = self.partial_shares.get(&key, working_set)
                .ok_or("Missing partial share")?;
            partials.push((*idx, partial.partial_sig.clone()));
        }
        
        // Lagrange interpolation to aggregate
        let aggregated = self.aggregate_bls_signatures(&partials, &validator_indices)?;
        
        let decryption_key = DecryptionKey {
            sigma: aggregated,
            round,
        };
        
        let key = (auction_id, round);
        self.decryption_keys.set(&key, &decryption_key, working_set);
        
        Ok(CallResponse::default()
            .add_event("decryption_key_aggregated", &[
                ("auction_id", &auction_id.to_string()),
                ("round", &round.to_string()),
            ]))
    }
    
    /// Verify DLEQ proof for partial signature
    fn verify_partial_signature_proof(
        &self,
        partial: &PartialDecryptionShare,
        validator_pubkey: &G1Point,
        identity: &[u8; 32],
    ) -> Result<(), Error> {
        // DLEQ proof verifies:
        // log_g(pk) == log_{H(id)}(partial_sig)
        // i.e., partial_sig = sk * H(id) where pk = sk * g
        
        use crate::crypto::bls;
        
        let id_point = bls::hash_to_g1(identity);
        
        let valid = bls::verify_dleq(
            &partial.proof,
            validator_pubkey,
            &partial.partial_sig,
            &id_point,
        );
        
        require!(valid, "Invalid DLEQ proof");
        Ok(())
    }
    
    /// Aggregate BLS partial signatures using Lagrange interpolation
    fn aggregate_bls_signatures(
        &self,
        partials: &[(u32, G1Point)],
        indices: &[u32],
    ) -> Result<G1Point, Error> {
        use crate::crypto::bls;
        
        // Compute Lagrange coefficients
        let coefficients = bls::lagrange_coefficients(indices);
        
        // Aggregate: σ = Σ λ_i · σ_i
        let aggregated = bls::aggregate_with_coefficients(partials, &coefficients);
        
        Ok(aggregated)
    }
}
```

---

## 7. SP1 Circuit Specification

### 7.1 SP1 Program

```rust
// ============================================================
// FILE: crates/circuit/src/main.rs
// SP1 guest program
// ============================================================

#![no_main]
sp1_zkvm::entrypoint!(main);

use auction_types::{
    SP1CircuitInput, AuctionPublicValues, AuctionTypeCompact,
    PedersenCommitment, G1Point,
};

/// Fixed second generator for Pedersen commitments
/// H = hash_to_curve("auction_pedersen_h")
fn pedersen_h() -> G1Point {
    // Deterministic nothing-up-my-sleeve point
    // In production, use RFC 9380 hash_to_curve
    G1Point([
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94,
        0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
        0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
        0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
        0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef,
        0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
    ])
}

/// Verify Pedersen commitment: C == g^value * h^randomness
fn verify_pedersen(
    commitment: &PedersenCommitment,
    value: u64,
    randomness: &[u8; 32],
) -> bool {
    // Use SP1's accelerated BLS12-381 operations
    use sp1_zkvm::precompiles::bls12_381::*;
    
    // g^value
    let g = g1_generator();
    let value_point = g1_scalar_mul(&g, &value.to_le_bytes());
    
    // h^randomness
    let h = decompress_g1(&pedersen_h().0);
    let random_point = g1_scalar_mul(&h, randomness);
    
    // C = g^value * h^randomness
    let expected = g1_add(&value_point, &random_point);
    let expected_compressed = compress_g1(&expected);
    
    expected_compressed == commitment.point.0
}

fn main() {
    // Read private inputs
    let input: SP1CircuitInput = sp1_zkvm::io::read();
    
    let n = input.commitments.len();
    assert!(n > 0, "No bids");
    assert_eq!(input.bid_values.len(), n, "Values count mismatch");
    assert_eq!(input.randomness.len(), n, "Randomness count mismatch");
    
    // ================================================================
    // STEP 1: Verify all Pedersen commitments
    // ================================================================
    
    let mut valid_bids: Vec<(usize, u64)> = Vec::new();
    
    for i in 0..n {
        let valid = verify_pedersen(
            &input.commitments[i],
            input.bid_values[i],
            &input.randomness[i],
        );
        
        if valid && input.bid_values[i] > 0 {
            valid_bids.push((i, input.bid_values[i]));
        }
    }
    
    assert!(!valid_bids.is_empty(), "No valid bids after verification");
    
    // ================================================================
    // STEP 2: Run auction logic
    // ================================================================
    
    let (winner_index, winning_price) = match input.auction_type {
        AuctionTypeCompact::FirstPrice => {
            first_price_auction(&valid_bids)
        },
        AuctionTypeCompact::SecondPrice => {
            second_price_auction(&valid_bids)
        },
        AuctionTypeCompact::GSP => {
            assert_eq!(input.quality_scores.len(), n, "Quality scores mismatch");
            gsp_auction(&valid_bids, &input.quality_scores)
        },
    };
    
    // ================================================================
    // STEP 3: Compute commitments hash
    // ================================================================
    
    let commitments_hash = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for c in &input.commitments {
            hasher.update(&c.point.0);
        }
        let result: [u8; 32] = hasher.finalize().into();
        result
    };
    
    // ================================================================
    // STEP 4: Output public values
    // ================================================================
    
    let public_values = AuctionPublicValues {
        auction_id: input.auction_id,
        commitments_hash,
        winner_index: winner_index as u32,
        winning_price,
        num_valid_bids: valid_bids.len() as u32,
    };
    
    sp1_zkvm::io::commit(&public_values);
}

/// First-price: winner pays their bid
fn first_price_auction(valid_bids: &[(usize, u64)]) -> (usize, u64) {
    let (idx, bid) = valid_bids.iter()
        .max_by_key(|(_, b)| *b)
        .unwrap();
    (*idx, *bid)
}

/// Second-price: winner pays second-highest bid
fn second_price_auction(valid_bids: &[(usize, u64)]) -> (usize, u64) {
    let mut sorted: Vec<_> = valid_bids.to_vec();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    
    let winner_idx = sorted[0].0;
    let price = if sorted.len() > 1 {
        sorted[1].1
    } else {
        sorted[0].1  // Single bidder pays their bid
    };
    
    (winner_idx, price)
}

/// GSP: rank by bid * quality_score, pay minimum to maintain position
fn gsp_auction(
    valid_bids: &[(usize, u64)],
    quality_scores: &[u32],
) -> (usize, u64) {
    // Compute effective bids
    let mut ranked: Vec<_> = valid_bids.iter()
        .map(|&(idx, bid)| {
            let qs = quality_scores[idx] as u64;
            let effective = bid.saturating_mul(qs);
            (idx, bid, effective)
        })
        .collect();
    
    // Sort by effective bid descending
    ranked.sort_by(|a, b| b.2.cmp(&a.2));
    
    let winner_idx = ranked[0].0;
    let winner_qs = quality_scores[winner_idx] as u64;
    
    // Price = ceil(next_effective / winner_qs) + 1 cent
    let price = if ranked.len() > 1 {
        let next_effective = ranked[1].2;
        (next_effective + winner_qs - 1) / winner_qs
    } else {
        1
    };
    
    (winner_idx, price)
}
```

### 7.2 SP1 Build Configuration

```toml
# crates/circuit/Cargo.toml

[package]
name = "auction-circuit"
version = "0.1.0"
edition = "2021"

[dependencies]
auction-types = { path = "../types" }
sp1-zkvm = "3.0"
sha2 = { version = "0.10", default-features = false }
borsh = { version = "1.0", default-features = false }

[features]
default = []
```

### 7.3 Prover SDK Usage

```rust
// ============================================================
// FILE: crates/settler/src/prover.rs
// ============================================================

use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues};
use auction_types::{SP1CircuitInput, SP1AuctionProof, AuctionPublicValues};

const ELF: &[u8] = include_bytes!("../../circuit/elf/auction-circuit");

pub struct SP1Prover {
    client: ProverClient,
}

impl SP1Prover {
    pub fn new() -> Self {
        Self {
            client: ProverClient::new(),
        }
    }
    
    /// Generate SP1 proof for auction settlement
    pub fn prove(&self, input: &SP1CircuitInput) -> Result<SP1AuctionProof, ProverError> {
        // Setup
        let (pk, vk) = self.client.setup(ELF);
        
        // Prepare stdin
        let mut stdin = SP1Stdin::new();
        stdin.write(input);
        
        // Generate proof (Groth16 for on-chain verification)
        let proof = self.client.prove(&pk, stdin)
            .groth16()
            .run()
            .map_err(|e| ProverError::ProvingFailed(e.to_string()))?;
        
        // Extract public values
        let public_values: AuctionPublicValues = proof.public_values.read();
        
        Ok(SP1AuctionProof {
            proof_bytes: proof.bytes(),
            public_values,
            vkey_hash: vk.hash_bytes().try_into().unwrap(),
        })
    }
    
    /// Get verification key for on-chain deployment
    pub fn verification_key(&self) -> Vec<u8> {
        let (_, vk) = self.client.setup(ELF);
        vk.bytes()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("Proving failed: {0}")]
    ProvingFailed(String),
}
```

---

## 8. Threshold Decryption Service

### 8.1 Settler Service

```rust
// ============================================================
// FILE: crates/settler/src/lib.rs
// Permissionless settlement service
// ============================================================

use auction_types::*;
use crate::prover::SP1Prover;

pub struct AuctionSettler {
    rollup_client: RollupClient,
    prover: SP1Prover,
}

impl AuctionSettler {
    pub fn new(rollup_url: String) -> Self {
        Self {
            rollup_client: RollupClient::new(rollup_url),
            prover: SP1Prover::new(),
        }
    }
    
    /// Settle an auction (anyone can call this)
    pub async fn settle(&self, auction_id: u64) -> Result<(), SettlerError> {
        // 1. Fetch auction config
        let auction = self.rollup_client.get_auction(auction_id).await?;
        
        // 2. Check auction is ready for settlement
        if auction.state != AuctionState::Decrypted {
            return Err(SettlerError::NotReady);
        }
        
        // 3. Fetch decryption key
        let decryption_key = self.rollup_client
            .get_decryption_key(auction_id, auction.decryption_round)
            .await?
            .ok_or(SettlerError::DecryptionKeyNotAvailable)?;
        
        // 4. Fetch all encrypted bids
        let bidders = self.rollup_client.get_bidders(auction_id).await?;
        let mut encrypted_bids = Vec::new();
        for bidder in &bidders {
            let bid = self.rollup_client.get_bid(auction_id, *bidder).await?;
            encrypted_bids.push(bid);
        }
        
        // 5. Decrypt all bids
        let decrypted_bids = self.decrypt_bids(&encrypted_bids, &decryption_key)?;
        
        // 6. Build circuit input
        let input = SP1CircuitInput {
            auction_id,
            auction_type: match &auction.auction_type {
                AuctionType::FirstPrice => AuctionTypeCompact::FirstPrice,
                AuctionType::SecondPrice => AuctionTypeCompact::SecondPrice,
                AuctionType::GeneralizedSecondPrice { .. } => AuctionTypeCompact::GSP,
            },
            commitments: encrypted_bids.iter().map(|b| b.commitment.clone()).collect(),
            bid_values: decrypted_bids.iter().map(|b| b.bid_value).collect(),
            randomness: decrypted_bids.iter().map(|b| b.randomness.0).collect(),
            quality_scores: match &auction.auction_type {
                AuctionType::GeneralizedSecondPrice { quality_scores } => {
                    bidders.iter()
                        .map(|b| {
                            quality_scores.iter()
                                .find(|(addr, _)| addr == b)
                                .map(|(_, s)| *s)
                                .unwrap_or(1)
                        })
                        .collect()
                },
                _ => vec![1; bidders.len()],
            },
        };
        
        // 7. Generate SP1 proof
        println!("Generating SP1 proof...");
        let proof = self.prover.prove(&input)?;
        println!("Proof generated!");
        
        // 8. Determine winner from proof
        let winner = bidders[proof.public_values.winner_index as usize];
        
        // 9. Submit settlement transaction
        let tx = AuctionCall::SettleAuction {
            auction_id,
            winner,
            winning_price: proof.public_values.winning_price,
            proof,
        };
        
        self.rollup_client.submit_transaction(tx).await?;
        
        println!("Auction {} settled! Winner: {:?}, Price: {}", 
                 auction_id, 
                 hex::encode(winner),
                 proof.public_values.winning_price);
        
        Ok(())
    }
    
    /// Decrypt bids using threshold decryption key
    fn decrypt_bids(
        &self,
        encrypted_bids: &[EncryptedBid],
        decryption_key: &DecryptionKey,
    ) -> Result<Vec<DecryptedBidValue>, SettlerError> {
        use crate::crypto::threshold_ibe;
        
        let mut decrypted = Vec::new();
        
        for (i, bid) in encrypted_bids.iter().enumerate() {
            let plaintext = threshold_ibe::decrypt(
                &bid.ciphertext,
                &decryption_key.sigma,
            )?;
            
            // Parse (bid_value, randomness) from plaintext
            let bid_value = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());
            let randomness = Scalar(plaintext[8..40].try_into().unwrap());
            
            decrypted.push(DecryptedBidValue {
                bidder: bid.bidder,
                bid_value,
                randomness,
                index: i,
            });
        }
        
        Ok(decrypted)
    }
}

#[derive(Debug)]
struct DecryptedBidValue {
    bidder: Address,
    bid_value: u64,
    randomness: Scalar,
    index: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SettlerError {
    #[error("Auction not ready for settlement")]
    NotReady,
    
    #[error("Decryption key not available")]
    DecryptionKeyNotAvailable,
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("RPC error: {0}")]
    RpcError(String),
    
    #[error("Proving error: {0}")]
    ProvingError(#[from] crate::prover::ProverError),
}
```

---

## 9. Client SDK

### 9.1 Bidder Client

```rust
// ============================================================
// FILE: crates/client/src/lib.rs
// ============================================================

use auction_types::*;

pub struct AuctionBidder {
    rollup_url: String,
    signer: Box<dyn Signer>,
}

impl AuctionBidder {
    pub fn new(rollup_url: String, signer: Box<dyn Signer>) -> Self {
        Self { rollup_url, signer }
    }
    
    /// Create and submit a bid
    pub async fn submit_bid(
        &self,
        auction_id: u64,
        bid_value: u64,
        deposit: u64,
    ) -> Result<BidReceipt, BidderError> {
        // 1. Fetch auction config
        let client = RollupClient::new(&self.rollup_url);
        let auction = client.get_auction(auction_id).await?;
        
        // 2. Fetch master public key
        let mpk = client.get_master_public_key().await?;
        
        // 3. Generate commitment randomness
        let mut randomness = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut randomness);
        
        // 4. Create Pedersen commitment
        let commitment = pedersen_commit(bid_value, &randomness);
        
        // 5. Encrypt bid using threshold IBE
        let plaintext = encode_bid_plaintext(bid_value, &randomness);
        let ciphertext = threshold_ibe_encrypt(
            &mpk.mpk,
            &auction.identity,
            &plaintext,
        )?;
        
        // 6. Submit transaction
        let tx = AuctionCall::SubmitBid {
            auction_id,
            commitment: commitment.clone(),
            ciphertext: ciphertext.clone(),
            deposit,
        };
        
        let signed_tx = self.signer.sign_transaction(tx)?;
        let tx_hash = client.submit_transaction(signed_tx).await?;
        
        // 7. Return receipt (client should save this!)
        Ok(BidReceipt {
            auction_id,
            bid_value,
            randomness,
            commitment,
            ciphertext,
            tx_hash,
            timestamp: std::time::SystemTime::now(),
        })
    }
    
    /// Query auction status
    pub async fn get_auction(&self, auction_id: u64) -> Result<AuctionConfig, BidderError> {
        let client = RollupClient::new(&self.rollup_url);
        client.get_auction(auction_id).await
            .map_err(BidderError::from)
    }
    
    /// Query result after settlement
    pub async fn get_result(&self, auction_id: u64) -> Result<Option<AuctionResult>, BidderError> {
        let client = RollupClient::new(&self.rollup_url);
        client.get_result(auction_id).await
            .map_err(BidderError::from)
    }
    
    /// Claim refund after settlement
    pub async fn claim_refund(&self, auction_id: u64) -> Result<TxHash, BidderError> {
        let client = RollupClient::new(&self.rollup_url);
        
        let tx = AuctionCall::ClaimRefund { auction_id };
        let signed_tx = self.signer.sign_transaction(tx)?;
        
        client.submit_transaction(signed_tx).await
            .map_err(BidderError::from)
    }
}

/// Receipt for submitted bid (client MUST save this)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BidReceipt {
    pub auction_id: u64,
    pub bid_value: u64,
    pub randomness: [u8; 32],
    pub commitment: PedersenCommitment,
    pub ciphertext: ThresholdCiphertext,
    pub tx_hash: TxHash,
    pub timestamp: std::time::SystemTime,
}

fn encode_bid_plaintext(bid_value: u64, randomness: &[u8; 32]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(40);
    plaintext.extend_from_slice(&bid_value.to_le_bytes());
    plaintext.extend_from_slice(randomness);
    plaintext
}
```

---

## 10. Cryptographic Primitives

### 10.1 Threshold IBE Implementation

```rust
// ============================================================
// FILE: crates/crypto/src/threshold_ibe.rs
// Commonware-compatible threshold IBE
// ============================================================

use blst::{min_pk::*, BLST_ERROR};
use auction_types::*;

/// Encrypt message using threshold IBE
pub fn encrypt(
    mpk: &G2Point,
    identity: &[u8; 32],
    plaintext: &[u8],
) -> Result<ThresholdCiphertext, CryptoError> {
    // 1. Hash identity to G1
    let id_point = hash_to_g1(identity);
    
    // 2. Generate random scalar r
    let mut r_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut r_bytes);
    let r = blst::blst_scalar::from_bendian(&r_bytes);
    
    // 3. Compute ephemeral pubkey U = r·G2
    let g2 = P2::generator();
    let u = g2.mult(&r.to_bendian());
    
    // 4. Compute shared secret via pairing: e(H(id), MPK)^r
    let mpk_point = P2::uncompress(&mpk.0)
        .map_err(|_| CryptoError::InvalidPoint)?;
    
    // e(id_point, mpk)^r = e(r·id_point, mpk)
    let r_id = id_point.mult(&r.to_bendian());
    let shared = pairing(&r_id, &mpk_point);
    
    // 5. Derive symmetric key
    let key = derive_aead_key(&shared.to_bendian());
    
    // 6. Encrypt with AES-GCM
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    
    let ciphertext_with_tag = cipher.encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    
    // Split ciphertext and tag
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let tag: [u8; 16] = ciphertext_with_tag[tag_start..].try_into().unwrap();
    
    Ok(ThresholdCiphertext {
        ephemeral_pubkey: G2Point(u.compress()),
        ciphertext,
        tag,
        nonce: nonce_bytes,
    })
}

/// Decrypt message using aggregated threshold signature
pub fn decrypt(
    ct: &ThresholdCiphertext,
    sigma: &G1Point,
) -> Result<Vec<u8>, CryptoError> {
    // 1. Parse ephemeral pubkey
    let u = P2::uncompress(&ct.ephemeral_pubkey.0)
        .map_err(|_| CryptoError::InvalidPoint)?;
    
    // 2. Parse decryption key (aggregated signature)
    let sig = P1::uncompress(&sigma.0)
        .map_err(|_| CryptoError::InvalidPoint)?;
    
    // 3. Compute shared secret: e(σ, U)
    let shared = pairing(&sig, &u);
    
    // 4. Derive symmetric key
    let key = derive_aead_key(&shared.to_bendian());
    
    // 5. Decrypt with AES-GCM
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&ct.nonce);
    
    // Reconstruct ciphertext with tag
    let mut ciphertext_with_tag = ct.ciphertext.clone();
    ciphertext_with_tag.extend_from_slice(&ct.tag);
    
    cipher.decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Hash to G1 (domain separation for auction identities)
pub fn hash_to_g1(data: &[u8]) -> P1 {
    P1::hash_to(data, b"AUCTION_IBE_V1", &[])
        .expect("hash_to_g1 should not fail")
}

/// Derive AEAD key from pairing result
fn derive_aead_key(pairing_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"AUCTION_AEAD_KEY_V1");
    hasher.update(pairing_bytes);
    hasher.finalize().into()
}

/// Compute pairing e(P1, P2)
fn pairing(p1: &P1, p2: &P2) -> blst::Gt {
    blst::pairing(p1, p2)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid point")]
    InvalidPoint,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}
```

### 10.2 BLS Utilities

```rust
// ============================================================
// FILE: crates/crypto/src/bls.rs
// ============================================================

use blst::min_pk::*;
use auction_types::*;

/// Compute Lagrange coefficient for index i given set of indices
pub fn lagrange_coefficient(i: u32, indices: &[u32]) -> blst::blst_scalar {
    let mut numerator = blst::blst_fr::one();
    let mut denominator = blst::blst_fr::one();
    
    let i_fr = blst::blst_fr::from_u64(i as u64);
    
    for &j in indices {
        if j != i {
            let j_fr = blst::blst_fr::from_u64(j as u64);
            
            // numerator *= -j
            let neg_j = j_fr.neg();
            numerator = numerator.mul(&neg_j);
            
            // denominator *= (i - j)
            let diff = i_fr.sub(&j_fr);
            denominator = denominator.mul(&diff);
        }
    }
    
    // λ_i = numerator / denominator
    let denom_inv = denominator.inverse();
    numerator.mul(&denom_inv).to_scalar()
}

/// Compute all Lagrange coefficients for a set of indices
pub fn lagrange_coefficients(indices: &[u32]) -> Vec<blst::blst_scalar> {
    indices.iter()
        .map(|&i| lagrange_coefficient(i, indices))
        .collect()
}

/// Aggregate partial signatures with Lagrange coefficients
pub fn aggregate_with_coefficients(
    partials: &[(u32, G1Point)],
    coefficients: &[blst::blst_scalar],
) -> G1Point {
    let mut result = P1::default();
    
    for ((_, partial), coeff) in partials.iter().zip(coefficients.iter()) {
        let p = P1::uncompress(&partial.0).expect("valid partial sig");
        let weighted = p.mult(&coeff.to_bendian());
        result = result.add(&weighted);
    }
    
    G1Point(result.compress())
}

/// Verify DLEQ proof: log_g(pk) == log_h(sig)
pub fn verify_dleq(
    proof: &DiscreteLogProof,
    pk: &G1Point,
    sig: &G1Point,
    h: &P1,
) -> bool {
    // Schnorr-style DLEQ verification
    let g = P1::generator();
    let pk_point = P1::uncompress(&pk.0).expect("valid pk");
    let sig_point = P1::uncompress(&sig.0).expect("valid sig");
    
    let c = blst::blst_scalar::from_bendian(&proof.challenge.0);
    let s = blst::blst_scalar::from_bendian(&proof.response.0);
    
    // Check: g^s == pk^c * R1  (where R1 is first part of commitment)
    // Check: h^s == sig^c * R2 (where R2 is second part of commitment)
    
    // Reconstruct R1 = g^s * pk^{-c}
    let g_s = g.mult(&s.to_bendian());
    let pk_c = pk_point.mult(&c.to_bendian());
    let r1 = g_s.add(&pk_c.neg());
    
    // Reconstruct R2 = h^s * sig^{-c}
    let h_s = h.mult(&s.to_bendian());
    let sig_c = sig_point.mult(&c.to_bendian());
    let r2 = h_s.add(&sig_c.neg());
    
    // Recompute challenge
    let mut hasher = sha2::Sha256::new();
    hasher.update(&g.compress());
    hasher.update(&h.compress());
    hasher.update(&pk.0);
    hasher.update(&sig.0);
    hasher.update(&r1.compress());
    hasher.update(&r2.compress());
    let expected_c: [u8; 32] = hasher.finalize().into();
    
    expected_c == proof.challenge.0
}
```

---

## 11. Testing Strategy

### 11.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threshold_encrypt_decrypt() {
        // Setup: Generate threshold keypair
        let (mpk, shares) = test_dkg(3, 5);  // 3-of-5 threshold
        
        // Encrypt
        let identity = [42u8; 32];
        let plaintext = b"secret bid: 100 tokens";
        let ct = threshold_ibe::encrypt(&mpk, &identity, plaintext).unwrap();
        
        // Generate partial decryptions from 3 parties
        let partials: Vec<_> = shares[0..3].iter()
            .map(|(idx, sk)| {
                let id_point = hash_to_g1(&identity);
                let partial = sk.sign(&id_point);
                (*idx, partial)
            })
            .collect();
        
        // Aggregate
        let coeffs = lagrange_coefficients(&[0, 1, 2]);
        let sigma = aggregate_with_coefficients(&partials, &coeffs);
        
        // Decrypt
        let decrypted = threshold_ibe::decrypt(&ct, &sigma).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_sp1_circuit_first_price() {
        // Run SP1 circuit locally (no proof)
        let input = SP1CircuitInput {
            auction_id: 1,
            auction_type: AuctionTypeCompact::FirstPrice,
            commitments: vec![/* ... */],
            bid_values: vec![100, 200, 150],
            randomness: vec![/* ... */],
            quality_scores: vec![],
        };
        
        // Execute in mock mode
        let output = sp1_sdk::execute(ELF, &input).unwrap();
        let public_values: AuctionPublicValues = output.public_values.read();
        
        assert_eq!(public_values.winner_index, 1);  // Highest bid
        assert_eq!(public_values.winning_price, 200);
    }
    
    #[test]
    fn test_pedersen_commitment() {
        let value = 1000u64;
        let randomness = [42u8; 32];
        
        let commitment = pedersen_commit(value, &randomness);
        
        // Verify opens correctly
        assert!(pedersen_verify(&commitment, value, &randomness));
        
        // Verify wrong value fails
        assert!(!pedersen_verify(&commitment, 1001, &randomness));
    }
}
```

### 11.2 Integration Tests

```rust
#[tokio::test]
async fn test_full_auction_with_threshold_encryption() {
    // 1. Setup: Deploy module with DKG
    // 2. Create auction
    // 3. Multiple bidders submit encrypted bids
    // 4. Advance time past end_time
    // 5. Validators submit partial decryptions
    // 6. Anyone aggregates decryption key
    // 7. Settler decrypts, proves, and settles
    // 8. Verify winner and refunds
}
```

---

## 12. Deployment Guide

### 12.1 Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install SP1
curl -L https://sp1.succinct.xyz | bash
sp1up

# Install blst (BLS library)
# Included as cargo dependency
```

### 12.2 Build Steps

```bash
# Clone repository
git clone https://github.com/your-org/zk-threshold-auction
cd zk-threshold-auction

# Build all crates
cargo build --release

# Build SP1 circuit
cd crates/circuit
cargo prove build --release

# The ELF will be at: target/elf/auction-circuit
```

### 12.3 DKG Ceremony

```bash
# Run distributed key generation (coordinate among validators)
./scripts/run_dkg.sh --threshold 67 --total 100

# Output:
# - master_public_key.json
# - validator_shares/ (distribute securely to each validator)
```

### 12.4 Genesis Configuration

```json
{
  "auction_module": {
    "master_public_key": {
      "mpk": "0x...",
      "threshold": 67,
      "total_validators": 100
    },
    "validator_pubkeys": [
      [0, "0x..."],
      [1, "0x..."]
    ],
    "sp1_vkey": "0x...",
    "sp1_vkey_hash": "0x..."
  }
}
```

---

## 13. Security Considerations

### 13.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Threshold collusion** | Requires t validators (67%) to collude |
| **Early decryption** | Impossible without t partial sigs |
| **Auction manipulation** | SP1 proof prevents incorrect results |
| **Bid modification** | Pedersen binding + on-chain ciphertext |
| **Front-running** | Ciphertexts finalized before decryption |
| **Settlement censorship** | Permissionless - anyone can settle |

### 13.2 Cryptographic Assumptions

- **BLS12-381 Security**: ~126-bit security
- **Threshold Security**: t-of-n honest majority
- **SP1 Soundness**: Computational soundness (Groth16)
- **Pedersen Binding**: Discrete log hardness

### 13.3 Liveness Considerations

```
LIVENESS REQUIREMENTS:

1. Threshold signature production:
   - Tied to consensus liveness
   - If chain is producing blocks, decryption keys are produced
   
2. Settlement:
   - Anyone can settle (no centralized dependency)
   - Economic incentive: settler can charge fee
   
3. Failure modes:
   - <t validators online: Decryption delayed (retry when threshold met)
   - No settler: Auction times out, deposits refundable
```

### 13.4 Comparison to v1 (Sequencer Model)

| Aspect | v1: Sequencer | v2: Threshold |
|--------|---------------|---------------|
| Privacy collusion | 1 party | 67% of validators |
| Liveness | Sequencer online | Chain liveness |
| Settlement | Sequencer only | Permissionless |
| Complexity | Lower | Higher |
| Setup | Key generation | Full DKG |

---

## Appendix A: SP1 Performance Estimates

Based on SP1 benchmarks (2024 data):

| Operation | Cycles | Estimated Time |
|-----------|--------|----------------|
| BLS G1 scalar mul | ~50K | 0.1ms |
| Pedersen verify (1) | ~100K | 0.2ms |
| Pedersen verify (100) | ~10M | 20ms |
| SHA256 (1KB) | ~20K | 0.04ms |
| Full auction (100 bids) | ~15M | 30ms execute |
| Groth16 proof gen | - | ~30s |

**Total settlement time for 100-bid auction**: ~30-60 seconds

---

## Appendix B: Gas Estimates

| Operation | Estimated Gas |
|-----------|---------------|
| CreateAuction | ~100K |
| SubmitBid | ~150K |
| SubmitPartialDecryption | ~80K |
| AggregateDecryptionKey | ~200K |
| SettleAuction (SP1 verify) | ~300K |

---

*End of Design Document v2.0*
