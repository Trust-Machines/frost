use num_traits::identities::Zero;
use rand_core::{CryptoRng, OsRng, RngCore};
use secp256k1_math::{point::Point, scalar::Scalar};
use std::{env, time};

mod frost;
mod schnorr;
mod util;
mod vss;

use frost::{Party, PublicNonce, PublicParty, Share, SignatureAggregator};

// This will eventually need to be replaced by rpcs
fn distribute_secret(parties: &mut Vec<Party>) {
    // round2
    for i in 0..parties.len() {
        for j in 0..parties.len() {
            if i == j {
                continue;
            }
            let share = parties[j].gen_share2(parties[i].id);
            parties[j].receive_share(share);
        }
    }

    for party in &mut parties.into_iter() {
        party.gen_secret();
    }
}

#[allow(non_snake_case)]
fn select_parties<RNG: RngCore + CryptoRng>(N: usize, T: usize, rng: &mut RNG) -> Vec<usize> {
    let mut indices: Vec<usize> = Vec::new();

    for i in 0..N {
        indices.push(i);
    }

    while indices.len() > T {
        let i = rng.next_u64() as usize % indices.len();
        indices.swap_remove(i);
    }

    indices
}

#[allow(non_snake_case)]
fn main() {
    let _args: Vec<String> = env::args().collect();
    let num_sigs = 1;
    let num_nonces = 5;

    let mut rng = OsRng::default();
    const N: usize = 10;
    const T: usize = 7;

    // Initial set-up
    let mut parties: Vec<Party> = (0..N)
        .map(|n| Party::new(&Scalar::from((n + 1) as u32), T, &mut rng))
        .collect();
    let A: Vec<Share> = parties.iter().map(|p| p.gen_share(&mut rng)).collect();
    let B: Vec<Vec<PublicNonce>> = parties
        .iter_mut()
        .map(|p| p.gen_nonces(num_nonces, &mut rng))
        .collect();
    distribute_secret(&mut parties); // maybe share Bs here as well?

    let mut public_parties: Vec<PublicParty> = parties
        .iter()
        .map(|party| PublicParty::from(&party))
        .collect();

    let mut sig_agg = SignatureAggregator::new(N, T, A, B);

    for _ in 0..num_sigs {
        let msg = "It was many and many a year ago".to_string();
        let signers = select_parties(N, T, &mut rng);

        // we're shadowing here, which seems okay
        let B = sig_agg.get_nonces(&signers);
        let rho: Vec<Scalar> = parties
            .iter()
            .map(|p| Party::gen_binding(&p.id, &B, &msg))
            .collect();
        let R_vec: Vec<Point> = (0..B.len()).map(|i| &B[i].D + &rho[i] * &B[i].E).collect();
        let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
        let S = parties.iter().map(|p| p.id).collect();

        // in prod the nodes would sign then send the z via p2p
        // once we receive them all go on to SA sign
        let sig_start = time::Instant::now();
        for i in &signers {
            let lambda = Party::gen_lambda(&public_parties[*i].id, &S);
            public_parties[*i].z =
                parties[*i].sign(&sig_agg.Y, &R, &msg, &rho[*i], &lambda, sig_agg.nonce_ctr);
        }
        let sig_time = sig_start.elapsed();
        println!(
            "Signing took {}ms for {} parties ",
            sig_time.as_micros(),
            parties.len()
        );

        let sig = sig_agg.sign(&msg, &public_parties, &signers);
        println!("Signature R,z = \n{},{}", sig.R, sig.z);
        assert!(sig.verify(&sig_agg.Y, &msg));
    }
}
