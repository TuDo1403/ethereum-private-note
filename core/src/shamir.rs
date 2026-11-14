//! Shamir sharing over GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1, byte by byte (SPEC.md, "Shares").

// 0x11b without its top bit is 0x1b. `a` is often a secret byte, so there are no data-dependent branches
// or loop counts: masks (0x00 or 0xff) replace the `if`s.
pub(crate) fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    for _ in 0..8 {
        p ^= a & (b & 1).wrapping_neg();
        a = (a << 1) ^ (0x1b & (a >> 7).wrapping_neg());
        b >>= 1;
    }
    p
}

fn ginv(a: u8) -> u8 {
    (0..254).fold(1, |r, _| gmul(r, a)) // a^254
}

/// Value of the share polynomial at x, byte by byte: coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 ... (Horner).
pub(crate) fn poly_at(coeffs: &[Vec<u8>], x: u8) -> [u8; 32] {
    std::array::from_fn(|i| coeffs.iter().rev().fold(0, |acc, c| gmul(acc, x) ^ c[i]))
}

/// The polynomial at 0 from k points with distinct nonzero x. In characteristic 2 "minus" is xor, so
/// the Lagrange weight of point i is the product over j != i of x_j / (x_i ^ x_j).
pub(crate) fn interpolate(points: &[(u8, [u8; 32])]) -> [u8; 32] {
    let mut secret = [0u8; 32];
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let weight = points
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .fold(1, |w, (_, &(xj, _))| gmul(w, gmul(xj, ginv(xi ^ xj))));
        for b in 0..32 {
            secret[b] ^= gmul(yi[b], weight);
        }
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_free_gmul_matches_the_textbook_one() {
        fn reference(mut a: u8, mut b: u8) -> u8 {
            let mut p = 0;
            while b != 0 {
                if b & 1 != 0 {
                    p ^= a;
                }
                a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
                b >>= 1;
            }
            p
        }
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gmul(a, b), reference(a, b), "{a} * {b}");
            }
        }
    }
}
