# Threshold-Encrypted Auction System

A ZK-proven private auction system built on Sovereign SDK with threshold BLS encryption and SP1 zkVM settlement.

## Overview

This system implements threshold-encrypted auctions where:

1. Bidders encrypt bids to a future round using threshold BLS Identity-Based Encryption (IBE)
2. Encrypted bids with Pedersen commitments are submitted on-chain
3. Validators produce a threshold signature at the designated round, enabling decryption
4. Anyone can decrypt, run the auction logic in SP1 zkVM, and submit a proof for settlement

**Key properties:**
- **Bid Privacy**: No single party can decrypt early (requires t-of-n validators)
- **Timelock**: Bids unlock at predetermined consensus round
- **Verifiable Correctness**: SP1 ZK proof guarantees auction rules are followed
- **Permissionless Settlement**: No trusted sequencer required
- **MEV Resistance**: Validators cannot see bid values when ordering transactions

## Repository Structure

```
threshold-auction/
├── Cargo.toml                    # Workspace configuration
├── zk-private-auction-design-v2.md  # Design specification
├── scripts/
│   └── test-deployment.sh        # Local test deployment script
└── crates/
    ├── types/                    # Core data structures
    ├── crypto/                   # Cryptographic primitives
    ├── module/                   # Sovereign SDK on-chain module
    ├── circuit/                  # SP1 zkVM circuit
    ├── settler/                  # Settlement service
    ├── client/                   # Bidder SDK + CLI
    ├── dkg/                      # Distributed key generation
    ├── decryption-coordinator/   # Threshold decryption coordination
    ├── mock-chain/               # Mock chain server for testing
    ├── validator/                # Validator node binary
    └── integration-tests/        # End-to-end tests
```

## Crates

### `auction-types`
Core type definitions shared across the system:
- **Cryptographic primitives**: `G1Point`, `G2Point`, `Scalar`, `PedersenCommitment`
- **Threshold encryption**: `ThresholdCiphertext`, `PartialDecryptionShare`, `DecryptionKey`, `MasterPublicKey`
- **Auction types**: `AuctionConfig`, `AuctionState`, `EncryptedBid`, `DecryptedBid`, `AuctionResult`
- **Proof types**: `SP1AuctionProof`, `AuctionPublicValues`

### `auction-crypto`
Threshold BLS encryption primitives compatible with Commonware's Battleware:
- **`ibe`**: Identity-Based Encryption using BLS12-381 pairings
- **`pedersen`**: Pedersen commitment scheme for bid binding
- **`threshold`**: Partial signature generation, verification (DLEQ proofs), and aggregation

### `auction-module`
Sovereign SDK module implementing on-chain auction logic:
- **`call`**: Transaction message types (`CreateAuction`, `SubmitBid`, `SubmitDecryptionKey`, `SettleAuction`)
- **`handlers`**: Business logic for processing transactions
- **`state`**: On-chain state structures
- **`queries`**: Read-only state access
- **`genesis`**: Initial configuration

### `auction-circuit`
SP1 zkVM circuit proving auction correctness:
- **`auction_logic`**: Winner determination for first-price, second-price, and GSP auctions
- **`commitment`**: Pedersen commitment verification
- **`program/`**: The SP1 guest program that runs inside the zkVM

The circuit proves:
1. All Pedersen commitments are correctly opened
2. The winner has the highest valid bid (or highest bid×quality for GSP)
3. The winning price is computed correctly per auction rules

### `auction-settler`
Permissionless settlement service:
- **`service`**: Monitors auctions, fetches encrypted bids and decryption keys
- **`prover`**: Generates SP1 proofs of auction correctness

Anyone can run this service to settle auctions and earn rewards.

### `auction-client`
SDK for bidders to participate in auctions:
- **`bid`**: `BidBuilder` for creating encrypted bids with commitments
- **`query`**: Functions for querying auction state

### `auction-dkg`
Distributed Key Generation using Feldman VSS:
- **`feldman`**: Polynomial generation, share evaluation, and verification
- **`participant`**: DKG protocol participant state machine
- **`types`**: `DkgConfig`, `DkgRound1Message`, `DkgRound2Message`, `DkgOutput`

Implements a (t, n) threshold setup where t validators must cooperate to produce a decryption key.

### `auction-decryption-coordinator`
Coordinates threshold decryption of auction bids:
- Collects partial decryption shares from validators
- Verifies DLEQ proofs on each share
- Aggregates shares using Lagrange interpolation once threshold is met
- Produces final decryption keys

Supports both single-request and batch decryption modes.

### `integration-tests`
End-to-end tests exercising the full auction lifecycle:
- DKG setup
- Auction creation
- Bid encryption and submission
- Threshold decryption
- Settlement with proof generation

## Supported Auction Types

| Type | Description |
|------|-------------|
| **First Price** | Winner pays their bid |
| **Second Price** | Winner pays second-highest bid |
| **Generalized Second Price (GSP)** | Rank by bid × quality score (Google Ads-style) |

## Dependencies

- **BLS12-381**: `blst`, `bls12_381`, `pairing` crates
- **Threshold crypto**: `vsss-rs` for Shamir secret sharing
- **SP1 zkVM**: `sp1-sdk`, `sp1-zkvm`
- **Serialization**: `borsh`, `serde`

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## Local Test Deployment

The repository includes a local test deployment infrastructure for development and testing.

### Quick Start

```bash
# Run full setup and demo
./scripts/test-deployment.sh all
```

This will:
1. Build all binaries
2. Generate validator keys (3 validators, threshold 2-of-3)
3. Start the mock chain server
4. Setup the chain with master public key
5. Run a demo auction with 3 bidders

### Manual Deployment

#### 1. Build Binaries

```bash
cargo build --release
```

#### 2. Generate Validator Keys

```bash
# Generate keys for 3 validators
./target/release/validator --index 1 --total 3 --threshold 2 --data-dir ./test-data/validators keygen
./target/release/validator --index 2 --total 3 --threshold 2 --data-dir ./test-data/validators keygen
./target/release/validator --index 3 --total 3 --threshold 2 --data-dir ./test-data/validators keygen
```

#### 3. Start Mock Chain

```bash
./target/release/mock-chain
# Server runs on http://127.0.0.1:9944
```

#### 4. Setup Chain with Master Key

```bash
./target/release/validator --index 1 --data-dir ./test-data/validators setup-chain
```

#### 5. Interact with CLI

```bash
# Get master public key
./target/release/auction-cli get-mpk

# Create an auction
./target/release/auction-cli create-auction \
    --sender "0101..." \
    --auction-type second_price \
    --start-time 1000 \
    --end-time 2000 \
    --decryption-round 2500 \
    --settlement-deadline 3000 \
    --min-bid 10

# Submit a bid
./target/release/auction-cli bid \
    --sender "alice..." \
    --auction-id 1 \
    --amount 100 \
    --deposit 100

# List auctions
./target/release/auction-cli list-auctions

# Get bids
./target/release/auction-cli get-bids --auction-id 1
```

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Deployment                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌────────────┐  │
│  │ Validator 1  │     │ Validator 2  │     │ Validator 3│  │
│  │ (keygen/dec) │     │ (keygen/dec) │     │ (keygen/dec)│ │
│  └──────┬───────┘     └──────┬───────┘     └─────┬──────┘  │
│         │                    │                   │         │
│         └────────────┬───────┴───────────────────┘         │
│                      │                                      │
│              ┌───────▼───────┐                             │
│              │  Mock Chain   │ (JSON-RPC on :9944)         │
│              │  (in-memory)  │                             │
│              └───────┬───────┘                             │
│                      │                                      │
│         ┌────────────┴────────────┐                        │
│         │                         │                        │
│   ┌─────▼─────┐            ┌──────▼──────┐                │
│   │ auction-  │            │   Bidders   │                │
│   │   cli     │            │  (clients)  │                │
│   └───────────┘            └─────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Binary | Description |
|--------|-------------|
| `mock-chain` | In-memory chain state with JSON-RPC server |
| `validator` | Generates keys, produces partial decryption shares |
| `auction-cli` | CLI for creating auctions and submitting bids |

## License

Apache-2.0
