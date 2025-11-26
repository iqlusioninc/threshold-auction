//! Auction winner determination logic.
//!
//! Implements different auction types:
//! - First-price: Winner pays their bid
//! - Second-price: Winner pays second-highest bid
//! - Generalized Second Price (GSP): Winner determined by bid * quality

use auction_types::circuit_io::AuctionTypeCompact;

/// Result of auction winner computation.
#[derive(Debug, Clone)]
pub struct AuctionWinner {
    /// Index of the winning bidder
    pub winner_index: u32,
    /// Price the winner pays
    pub winning_price: u64,
    /// Number of valid bids considered
    pub num_valid_bids: u32,
}

/// Compute the winner for any auction type.
pub fn compute_winner(
    auction_type: &AuctionTypeCompact,
    bid_values: &[u64],
    quality_scores: &[u32],
    reserve_price: Option<u64>,
) -> Option<AuctionWinner> {
    // Filter bids meeting reserve price
    let reserve = reserve_price.unwrap_or(0);
    let valid_bids: Vec<(usize, u64)> = bid_values
        .iter()
        .enumerate()
        .filter(|(_, &bid)| bid >= reserve)
        .map(|(i, &bid)| (i, bid))
        .collect();

    if valid_bids.is_empty() {
        return None;
    }

    match auction_type {
        AuctionTypeCompact::FirstPrice => compute_first_price_winner(&valid_bids, reserve),
        AuctionTypeCompact::SecondPrice => compute_second_price_winner(&valid_bids, reserve),
        AuctionTypeCompact::GSP => {
            compute_gsp_winner(&valid_bids, quality_scores, reserve)
        }
    }
}

/// Compute winner for first-price auction.
///
/// Winner pays their bid.
fn compute_first_price_winner(valid_bids: &[(usize, u64)], _reserve: u64) -> Option<AuctionWinner> {
    let (winner_idx, highest_bid) = valid_bids
        .iter()
        .max_by_key(|(_, bid)| bid)?;

    Some(AuctionWinner {
        winner_index: *winner_idx as u32,
        winning_price: *highest_bid,
        num_valid_bids: valid_bids.len() as u32,
    })
}

/// Compute winner for second-price (Vickrey) auction.
///
/// Winner pays the second-highest bid (or reserve if only one bid).
pub fn compute_second_price_winner(
    valid_bids: &[(usize, u64)],
    reserve: u64,
) -> Option<AuctionWinner> {
    if valid_bids.is_empty() {
        return None;
    }

    // Sort by bid descending
    let mut sorted: Vec<_> = valid_bids.to_vec();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let (winner_idx, _highest_bid) = sorted[0];

    // Second price is the second-highest bid, or reserve if only one bid
    let winning_price = if sorted.len() > 1 {
        sorted[1].1
    } else {
        reserve
    };

    Some(AuctionWinner {
        winner_index: winner_idx as u32,
        winning_price,
        num_valid_bids: valid_bids.len() as u32,
    })
}

/// Compute winner for Generalized Second Price (GSP) auction.
///
/// Used in ad auctions like Google Ads:
/// - Rank by bid * quality_score
/// - Winner pays: (next_rank_score / winner_quality) + 0.01
pub fn compute_gsp_winner(
    valid_bids: &[(usize, u64)],
    quality_scores: &[u32],
    reserve: u64,
) -> Option<AuctionWinner> {
    if valid_bids.is_empty() {
        return None;
    }

    // Compute rank scores: bid * quality
    let mut ranked: Vec<(usize, u64, u64)> = valid_bids
        .iter()
        .map(|(idx, bid)| {
            let quality = quality_scores.get(*idx).copied().unwrap_or(100) as u64;
            let score = bid * quality;
            (*idx, *bid, score)
        })
        .collect();

    // Sort by score descending
    ranked.sort_by(|a, b| b.2.cmp(&a.2));

    let (winner_idx, _winner_bid, winner_score) = ranked[0];
    let winner_quality = quality_scores.get(winner_idx).copied().unwrap_or(100) as u64;

    // GSP price: (next_score / winner_quality) + minimum increment
    let winning_price = if ranked.len() > 1 {
        let next_score = ranked[1].2;
        // Price = next_score / winner_quality (rounded up) + 1 (minimum increment)
        (next_score + winner_quality - 1) / winner_quality + 1
    } else {
        // Only one bidder: pay reserve
        reserve
    };

    Some(AuctionWinner {
        winner_index: winner_idx as u32,
        winning_price,
        num_valid_bids: valid_bids.len() as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_price_auction() {
        let bids = vec![(0, 100), (1, 200), (2, 150)];
        let result = compute_first_price_winner(&bids, 0).unwrap();

        assert_eq!(result.winner_index, 1);
        assert_eq!(result.winning_price, 200);
        assert_eq!(result.num_valid_bids, 3);
    }

    #[test]
    fn test_second_price_auction() {
        let bids = vec![(0, 100), (1, 200), (2, 150)];
        let result = compute_second_price_winner(&bids, 0).unwrap();

        assert_eq!(result.winner_index, 1);
        assert_eq!(result.winning_price, 150); // Second highest bid
        assert_eq!(result.num_valid_bids, 3);
    }

    #[test]
    fn test_second_price_single_bidder() {
        let bids = vec![(0, 100)];
        let result = compute_second_price_winner(&bids, 50).unwrap();

        assert_eq!(result.winner_index, 0);
        assert_eq!(result.winning_price, 50); // Reserve price
    }

    #[test]
    fn test_gsp_auction() {
        // Bidder 0: bid=100, quality=100, score=10000
        // Bidder 1: bid=80, quality=150, score=12000 (winner)
        // Bidder 2: bid=90, quality=110, score=9900
        let bids = vec![(0, 100), (1, 80), (2, 90)];
        let quality_scores = vec![100, 150, 110];

        let result = compute_gsp_winner(&bids, &quality_scores, 0).unwrap();

        assert_eq!(result.winner_index, 1); // Highest score wins
        // Price = (10000 / 150) + 1 = 67 + 1 = 68
        assert!(result.winning_price <= 80); // Should be less than winner's bid
    }

    #[test]
    fn test_reserve_price_filtering() {
        let bid_values = vec![50, 100, 150];
        let result = compute_winner(
            &AuctionTypeCompact::SecondPrice,
            &bid_values,
            &[],
            Some(75),
        )
        .unwrap();

        // Only bids >= 75 are valid (100, 150)
        assert_eq!(result.num_valid_bids, 2);
        assert_eq!(result.winner_index, 2); // Index of 150
        assert_eq!(result.winning_price, 100); // Second price among valid bids
    }

    #[test]
    fn test_no_valid_bids() {
        let bid_values = vec![50, 60];
        let result = compute_winner(
            &AuctionTypeCompact::FirstPrice,
            &bid_values,
            &[],
            Some(100), // Reserve higher than all bids
        );

        assert!(result.is_none());
    }
}
