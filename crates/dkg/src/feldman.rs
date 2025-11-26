//! Feldman Verifiable Secret Sharing.
//!
//! Extends Shamir's secret sharing with commitments that allow
//! verification of shares without revealing the secret.

use bls12_381::{G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::{CryptoRng, RngCore};

use auction_types::G2Point;

/// Generate a random polynomial of degree t-1 with given constant term.
///
/// Returns coefficients [a_0, a_1, ..., a_{t-1}] where:
/// - a_0 is the secret (constant term)
/// - f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
pub fn generate_polynomial<R: RngCore + CryptoRng>(
    secret: &Scalar,
    degree: usize,
    rng: &mut R,
) -> Vec<Scalar> {
    let mut coefficients = Vec::with_capacity(degree);
    coefficients.push(*secret);

    for _ in 1..degree {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        coefficients.push(Scalar::from_bytes_wide(&bytes));
    }

    coefficients
}

/// Evaluate polynomial at a point.
///
/// f(x) = a_0 + a_1*x + a_2*x^2 + ... using Horner's method
pub fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    for coeff in coefficients.iter().rev() {
        result = result * x + coeff;
    }
    result
}

/// Generate Feldman commitments for polynomial coefficients.
///
/// C_i = g^{a_i} for each coefficient a_i
pub fn generate_commitments(coefficients: &[Scalar]) -> Vec<G2Point> {
    coefficients
        .iter()
        .map(|coeff| {
            let point = (G2Projective::generator() * coeff).to_affine();
            G2Point(point.to_compressed())
        })
        .collect()
}

/// Verify a share against Feldman commitments.
///
/// Checks that g^{share} = Π C_i^{x^i}
pub fn verify_share(
    share: &Scalar,
    recipient_index: u32,
    commitments: &[G2Point],
) -> bool {
    // Compute LHS: g^{share}
    let lhs = (G2Projective::generator() * share).to_affine();

    // Compute RHS: Π C_i^{x^i} where x = recipient_index
    let x = Scalar::from(recipient_index as u64);
    let mut x_power = Scalar::ONE;
    let mut rhs = G2Projective::identity();

    for commitment in commitments {
        let c = G2Affine::from_compressed(&commitment.0);
        if c.is_none().into() {
            return false;
        }
        let c = c.unwrap();
        rhs += G2Projective::from(c) * x_power;
        x_power *= x;
    }

    lhs == rhs.to_affine()
}

/// Combine shares using Lagrange interpolation to reconstruct secret.
///
/// Given shares (x_i, y_i), computes f(0) = Σ y_i * λ_i
/// where λ_i = Π_{j≠i} (x_j / (x_j - x_i))
pub fn combine_shares(shares: &[(u32, Scalar)]) -> Option<Scalar> {
    if shares.is_empty() {
        return None;
    }

    let mut result = Scalar::ZERO;

    for (i, (x_i, y_i)) in shares.iter().enumerate() {
        let x_i_scalar = Scalar::from(*x_i as u64);

        // Compute Lagrange coefficient λ_i
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;

        for (j, (x_j, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j_scalar = Scalar::from(*x_j as u64);

            // numerator *= x_j (evaluating at 0)
            numerator *= x_j_scalar;

            // denominator *= (x_j - x_i)
            denominator *= x_j_scalar - x_i_scalar;
        }

        // λ_i = numerator / denominator
        let denom_inv = denominator.invert();
        if denom_inv.is_none().into() {
            return None;
        }
        let lambda_i = numerator * denom_inv.unwrap();

        // result += y_i * λ_i
        result += y_i * lambda_i;
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_scalar() -> Scalar {
        let mut rng = OsRng;
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_wide(&bytes)
    }

    #[test]
    fn test_polynomial_evaluation() {
        // f(x) = 5 + 3x + 2x^2
        let coeffs = vec![
            Scalar::from(5u64),
            Scalar::from(3u64),
            Scalar::from(2u64),
        ];

        // f(0) = 5
        assert_eq!(evaluate_polynomial(&coeffs, &Scalar::ZERO), Scalar::from(5u64));

        // f(1) = 5 + 3 + 2 = 10
        assert_eq!(evaluate_polynomial(&coeffs, &Scalar::ONE), Scalar::from(10u64));

        // f(2) = 5 + 6 + 8 = 19
        assert_eq!(
            evaluate_polynomial(&coeffs, &Scalar::from(2u64)),
            Scalar::from(19u64)
        );
    }

    #[test]
    fn test_share_verification() {
        let mut rng = OsRng;
        let secret = random_scalar();
        let threshold = 3;

        // Generate polynomial
        let coeffs = generate_polynomial(&secret, threshold, &mut rng);

        // Generate commitments
        let commitments = generate_commitments(&coeffs);

        // Generate and verify shares
        for i in 1..=5 {
            let x = Scalar::from(i as u64);
            let share = evaluate_polynomial(&coeffs, &x);
            assert!(verify_share(&share, i, &commitments));
        }
    }

    #[test]
    fn test_share_reconstruction() {
        let mut rng = OsRng;
        let secret = random_scalar();
        let threshold = 3;

        // Generate polynomial
        let coeffs = generate_polynomial(&secret, threshold, &mut rng);

        // Generate shares
        let shares: Vec<(u32, Scalar)> = (1..=5)
            .map(|i| {
                let x = Scalar::from(i as u64);
                (i, evaluate_polynomial(&coeffs, &x))
            })
            .collect();

        // Reconstruct from threshold shares
        let reconstructed = combine_shares(&shares[..3]).unwrap();
        assert_eq!(reconstructed, secret);

        // Reconstruct from different subset
        let reconstructed2 = combine_shares(&shares[2..5]).unwrap();
        assert_eq!(reconstructed2, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let mut rng = OsRng;
        let secret = random_scalar();
        let threshold = 3;

        let coeffs = generate_polynomial(&secret, threshold, &mut rng);

        // Only 2 shares (need 3)
        let shares: Vec<(u32, Scalar)> = (1..=2)
            .map(|i| {
                let x = Scalar::from(i as u64);
                (i, evaluate_polynomial(&coeffs, &x))
            })
            .collect();

        // This will "work" mathematically but give wrong result
        let reconstructed = combine_shares(&shares).unwrap();
        // With insufficient shares, we don't get the secret
        // (except by chance, which is negligible)
        // This test just verifies the function runs without panicking
    }
}
