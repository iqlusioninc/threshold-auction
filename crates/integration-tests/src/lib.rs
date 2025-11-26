//! End-to-end integration tests for the threshold auction system.
//!
//! These tests exercise the full auction lifecycle:
//! 1. DKG setup
//! 2. Auction creation
//! 3. Bid encryption and submission
//! 4. Threshold decryption
//! 5. Settlement with proof generation

use auction_client::create_bid;
use auction_crypto::{
    decrypt, encrypt, pedersen_commit, pedersen_verify, IbeParams, PedersenParams,
};
use auction_dkg::{
    feldman::{evaluate_polynomial, generate_commitments, generate_polynomial, verify_share},
    DkgConfig, DkgParticipant,
};
use auction_settler::prover::generate_mock_proof;
use auction_types::{
    circuit_io::AuctionTypeCompact, compute_auction_identity, AuctionConfig, AuctionMetadata,
    AuctionState, AuctionType, DecryptionKey, EncryptedBid, G1Point, G2Point, MasterPublicKey,
    PedersenCommitment,
};

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use rand::RngCore;

/// Test the complete auction flow with mock components.
#[test]
fn test_full_auction_flow() {
    let mut rng = OsRng;

    // ========================================
    // Phase 1: Setup - Generate threshold keys
    // ========================================

    // For simplicity, use a single master secret (in real system, this would be DKG)
    let master_secret = random_scalar(&mut rng);
    let mpk = (G2Projective::generator() * master_secret).to_affine();
    let mpk_bytes = G2Point(mpk.to_compressed());

    println!("Setup complete: Master public key generated");

    // ========================================
    // Phase 2: Create auction
    // ========================================

    let auction_id = 1u64;
    let decryption_round = 100u64;
    let identity = compute_auction_identity(auction_id, decryption_round);

    let auction_config = AuctionConfig {
        auction_id,
        creator: [0u8; 32],
        auction_type: AuctionType::SecondPrice,
        state: AuctionState::Open,
        start_time: 0,
        end_time: 1000,
        decryption_round,
        settlement_deadline: 2000,
        min_bid: 10,
        reserve_price: Some(50),
        identity,
        metadata: AuctionMetadata::default(),
    };

    println!("Auction {} created", auction_id);

    // ========================================
    // Phase 3: Bidders submit encrypted bids
    // ========================================

    // Create 3 bidders with different bid amounts
    let bidder_a = [1u8; 32];
    let bidder_b = [2u8; 32];
    let bidder_c = [3u8; 32];

    let bid_a = 100u64;
    let bid_b = 200u64;
    let bid_c = 150u64;

    // Create bids using the client SDK
    let prepared_bid_a = create_bid(&mpk_bytes, auction_id, decryption_round, bid_a, &mut rng)
        .expect("Failed to create bid A");

    let prepared_bid_b = create_bid(&mpk_bytes, auction_id, decryption_round, bid_b, &mut rng)
        .expect("Failed to create bid B");

    let prepared_bid_c = create_bid(&mpk_bytes, auction_id, decryption_round, bid_c, &mut rng)
        .expect("Failed to create bid C");

    // Create encrypted bid records (as they would be stored on-chain)
    let encrypted_bids = vec![
        EncryptedBid {
            bidder: bidder_a,
            commitment: prepared_bid_a.commitment.clone(),
            ciphertext: prepared_bid_a.ciphertext.clone(),
            deposit: bid_a,
            timestamp: 500,
        },
        EncryptedBid {
            bidder: bidder_b,
            commitment: prepared_bid_b.commitment.clone(),
            ciphertext: prepared_bid_b.ciphertext.clone(),
            deposit: bid_b,
            timestamp: 501,
        },
        EncryptedBid {
            bidder: bidder_c,
            commitment: prepared_bid_c.commitment.clone(),
            ciphertext: prepared_bid_c.ciphertext.clone(),
            deposit: bid_c,
            timestamp: 502,
        },
    ];

    println!("3 bids submitted");

    // ========================================
    // Phase 4: Threshold decryption
    // ========================================

    // Generate decryption key (in real system, validators would produce partial signatures)
    let id_hash = hash_to_g1(&identity);
    let sigma = (G1Projective::from(id_hash) * master_secret).to_affine();
    let decryption_key = DecryptionKey {
        sigma: G1Point(sigma.to_compressed()),
        round: decryption_round,
    };

    println!("Decryption key released at round {}", decryption_round);

    // Decrypt all bids
    let mut decrypted_bids = Vec::new();
    for (i, bid) in encrypted_bids.iter().enumerate() {
        let plaintext = decrypt(&bid.ciphertext, &decryption_key.sigma)
            .expect(&format!("Failed to decrypt bid {}", i));

        // Parse bid value and randomness from plaintext
        let bid_value = u64::from_le_bytes(plaintext[..8].try_into().unwrap());
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&plaintext[8..40]);

        decrypted_bids.push((bid_value, randomness));
        println!("Decrypted bid {}: value={}", i, bid_value);
    }

    // Verify decrypted values match original
    assert_eq!(decrypted_bids[0].0, bid_a);
    assert_eq!(decrypted_bids[1].0, bid_b);
    assert_eq!(decrypted_bids[2].0, bid_c);

    println!("All bids decrypted and verified");

    // ========================================
    // Phase 5: Settlement with proof
    // ========================================

    let commitments: Vec<PedersenCommitment> = encrypted_bids
        .iter()
        .map(|b| b.commitment.clone())
        .collect();

    let bid_values: Vec<u64> = decrypted_bids.iter().map(|(v, _)| *v).collect();
    let randomness: Vec<[u8; 32]> = decrypted_bids.iter().map(|(_, r)| *r).collect();

    let proof = generate_mock_proof(
        auction_id,
        AuctionTypeCompact::SecondPrice,
        commitments,
        bid_values,
        randomness,
        vec![], // No quality scores for second-price auction
        Some(50),
    )
    .expect("Failed to generate proof");

    println!("Settlement proof generated");
    println!("  Winner index: {}", proof.public_values.winner_index);
    println!("  Winning price: {}", proof.public_values.winning_price);
    println!("  Valid bids: {}", proof.public_values.num_valid_bids);

    // Verify results
    assert_eq!(proof.public_values.winner_index, 1); // Bidder B (highest bid)
    assert_eq!(proof.public_values.winning_price, 150); // Second-highest bid
    assert_eq!(proof.public_values.num_valid_bids, 3);

    println!("\nAuction settled successfully!");
    println!("  Winner: Bidder B");
    println!("  Payment: 150 (second-price)");
}

/// Test GSP (Generalized Second Price) auction.
#[test]
fn test_gsp_auction() {
    let mut rng = OsRng;

    let master_secret = random_scalar(&mut rng);
    let mpk = (G2Projective::generator() * master_secret).to_affine();
    let mpk_bytes = G2Point(mpk.to_compressed());

    let auction_id = 2u64;
    let decryption_round = 200u64;

    // Create bids
    let bid_a = create_bid(&mpk_bytes, auction_id, decryption_round, 100, &mut rng).unwrap();
    let bid_b = create_bid(&mpk_bytes, auction_id, decryption_round, 80, &mut rng).unwrap();

    // Quality scores: A=100, B=150
    // Scores: A=100*100=10000, B=80*150=12000
    // Winner: B (higher score)
    let quality_scores = vec![100u32, 150u32];

    let commitments = vec![bid_a.commitment.clone(), bid_b.commitment.clone()];

    let proof = generate_mock_proof(
        auction_id,
        AuctionTypeCompact::GSP,
        commitments,
        vec![100, 80],
        vec![[0u8; 32], [0u8; 32]],
        quality_scores,
        None,
    )
    .expect("Failed to generate GSP proof");

    assert_eq!(proof.public_values.winner_index, 1); // B wins due to higher score
    assert!(proof.public_values.winning_price < 80); // GSP price < winner's bid
}

/// Test Pedersen commitment binding property.
#[test]
fn test_commitment_binding() {
    let mut rng = OsRng;
    let params = PedersenParams::new();

    let value = 1000u64;
    let (commitment, randomness) = pedersen_commit(&params, value, &mut rng);

    // Verify correct opening succeeds
    assert!(pedersen_verify(&params, &commitment, value, &randomness).is_ok());

    // Verify wrong value fails
    assert!(pedersen_verify(&params, &commitment, value + 1, &randomness).is_err());
}

/// Test threshold signature aggregation.
#[test]
fn test_threshold_aggregation() {
    let mut rng = OsRng;

    // Create a 2-of-3 threshold setup
    let threshold = 2usize;
    let n = 3u32;

    // Generate master secret and polynomial
    let master_secret = random_scalar(&mut rng);
    let polynomial = generate_polynomial(&master_secret, threshold, &mut rng);
    let commitments = generate_commitments(&polynomial);

    // Generate shares for each validator
    let shares: Vec<(u32, Scalar)> = (1..=n)
        .map(|i| {
            let x = Scalar::from(i as u64);
            let share = evaluate_polynomial(&polynomial, &x);
            (i, share)
        })
        .collect();

    // Verify each share
    for (idx, share) in &shares {
        assert!(
            verify_share(share, *idx, &commitments),
            "Share {} verification failed",
            idx
        );
    }

    println!("All {} shares verified", n);

    // Verify we can reconstruct with threshold shares
    let threshold_shares: Vec<(u32, Scalar)> = shares[..threshold].to_vec();
    let reconstructed = auction_dkg::feldman::combine_shares(&threshold_shares).unwrap();
    assert_eq!(reconstructed, master_secret);

    println!("Master secret successfully reconstructed from {} shares", threshold);
}

/// Test bid encryption and decryption.
#[test]
fn test_bid_encryption_decryption() {
    let mut rng = OsRng;

    let master_secret = random_scalar(&mut rng);
    let mpk = (G2Projective::generator() * master_secret).to_affine();
    let ibe_params = IbeParams { mpk };

    let identity = b"test_auction:round:42";
    let bid_value = 12345u64;

    // Prepare plaintext (value + randomness)
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&bid_value.to_le_bytes());
    plaintext.extend_from_slice(&[0u8; 32]); // randomness placeholder

    // Encrypt
    let ciphertext = encrypt(&ibe_params, identity, &plaintext, &mut rng)
        .expect("Encryption failed");

    // Generate decryption key
    let id_hash = hash_to_g1(identity);
    let sigma = (G1Projective::from(id_hash) * master_secret).to_affine();
    let decryption_key = G1Point(sigma.to_compressed());

    // Decrypt
    let decrypted = decrypt(&ciphertext, &decryption_key)
        .expect("Decryption failed");

    let recovered_value = u64::from_le_bytes(decrypted[..8].try_into().unwrap());
    assert_eq!(recovered_value, bid_value);
}

/// Test that wrong decryption key fails.
#[test]
fn test_wrong_identity_decryption_fails() {
    let mut rng = OsRng;

    let master_secret = random_scalar(&mut rng);
    let mpk = (G2Projective::generator() * master_secret).to_affine();
    let ibe_params = IbeParams { mpk };

    let correct_identity = b"auction:1:round:100";
    let wrong_identity = b"auction:1:round:101";
    let plaintext = b"secret bid";

    let ciphertext = encrypt(&ibe_params, correct_identity, plaintext, &mut rng).unwrap();

    // Generate decryption key for wrong identity
    let wrong_id_hash = hash_to_g1(wrong_identity);
    let wrong_sigma = (G1Projective::from(wrong_id_hash) * master_secret).to_affine();
    let wrong_key = G1Point(wrong_sigma.to_compressed());

    // Decryption should fail
    assert!(decrypt(&ciphertext, &wrong_key).is_err());
}

/// Test DKG participant rounds.
#[test]
fn test_dkg_rounds() {
    let mut rng = OsRng;

    let config1 = DkgConfig::new(3, 2, 1);
    let config2 = DkgConfig::new(3, 2, 2);
    let config3 = DkgConfig::new(3, 2, 3);

    let mut p1 = DkgParticipant::new(config1);
    let mut p2 = DkgParticipant::new(config2);
    let mut p3 = DkgParticipant::new(config3);

    // Round 1: Generate commitments
    let msg1 = p1.round1(&mut rng);
    let msg2 = p2.round1(&mut rng);
    let msg3 = p3.round1(&mut rng);

    // All participants receive all round 1 messages
    p1.process_round1(msg1.clone()).unwrap();
    p1.process_round1(msg2.clone()).unwrap();
    p1.process_round1(msg3.clone()).unwrap();

    p2.process_round1(msg1.clone()).unwrap();
    p2.process_round1(msg2.clone()).unwrap();
    p2.process_round1(msg3.clone()).unwrap();

    p3.process_round1(msg1).unwrap();
    p3.process_round1(msg2).unwrap();
    p3.process_round1(msg3).unwrap();

    println!("DKG Round 1 complete: Commitments exchanged");

    // Round 2: Generate and distribute shares
    let shares1 = p1.round2().unwrap();
    let shares2 = p2.round2().unwrap();
    let shares3 = p3.round2().unwrap();

    assert_eq!(shares1.len(), 3);
    assert_eq!(shares2.len(), 3);
    assert_eq!(shares3.len(), 3);

    println!("DKG Round 2 complete: Shares generated");
}

// Helper functions

fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_wide(&bytes)
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
