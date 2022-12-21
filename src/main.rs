use rand_core::{CryptoRng, OsRng, RngCore};
use std::{env, time};

use frost::frost::{Party, PolyCommitment, PublicNonce, SignatureAggregator, SignatureShare};

use hashbrown::HashMap;

// This will eventually need to be replaced by rpcs
#[allow(non_snake_case)]
fn distribute(
    parties: &mut Vec<Party>,
    A: &Vec<PolyCommitment>,
    B: &Vec<Vec<PublicNonce>>,
) -> (u128, usize) {
    // each party broadcasts their commitments
    // these hashmaps will need to be serialized in tuples w/ the value encrypted
    let mut broadcast_shares = Vec::new();
    for i in 0..parties.len() {
        broadcast_shares.push(parties[i].get_shares());
    }

    let mut total_compute_secret_time = 0;

    // each party collects its shares from the broadcasts
    // maybe this should collect into a hashmap first?
    for i in 0..parties.len() {
        let mut h = HashMap::new();
        for j in 0..parties.len() {
            h.insert(j, broadcast_shares[j][&i]);
        }
        let compute_secret_start = time::Instant::now();
        parties[i].compute_secret(h, &A);
        let compute_secret_time = compute_secret_start.elapsed();
        total_compute_secret_time += compute_secret_time.as_micros();
    }

    // each party copies the nonces
    for i in 0..parties.len() {
        parties[i].set_group_nonces(B.clone());
    }

    let total_transmitted_bandwidth = serialized_size(&broadcast_shares)
        + serialized_size(&A) * parties.len()
        + serialized_size(&B) * parties.len();

    (total_compute_secret_time, total_transmitted_bandwidth)
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

// There might be a slick one-liner for this?
fn collect_signatures(
    parties: &Vec<Party>,
    signers: &Vec<usize>,
    nonce_ctr: usize,
    msg: &String,
) -> Vec<SignatureShare> {
    let mut sigs = Vec::new();
    for i in 0..signers.len() {
        let party = &parties[signers[i]];
        sigs.push(SignatureShare {
            id: party.id.clone(),
            z_i: party.sign(&msg, &signers, nonce_ctr),
            public_key: party.public_key.clone(),
        });
    }
    sigs
}

// In case one party loses their nonces & needs to regenerate
#[allow(non_snake_case)]
fn reset_nonce<RNG: RngCore + CryptoRng>(
    parties: &mut Vec<Party>,
    sa: &mut SignatureAggregator,
    i: usize,
    num_nonces: u32,
    rng: &mut RNG,
) {
    let B = &parties[i].gen_nonces(num_nonces, rng);
    for p in parties {
        p.set_party_nonces(i, B.clone());
    }
    sa.set_party_nonces(i, B.clone());
}

// Size in bytes after serializing obj
fn serialized_size<T: serde::Serialize>(obj: &T) -> usize {
    bincode::serialize(obj)
        .expect("Bincode serialization failed")
        .len()
}

#[allow(non_snake_case)]
fn main() {
    let args: Vec<String> = env::args().collect();
    let num_sigs = 7;
    let num_nonces = 5;
    let N: usize = if args.len() > 1 {
        args[1].parse::<usize>().unwrap()
    } else {
        10
    };
    let T: usize = if args.len() > 2 {
        args[2].parse::<usize>().unwrap()
    } else {
        (N * 2) / 3
    };

    let mut rng = OsRng::default();

    // Initial set-up
    let mut parties: Vec<Party> = (0..N).map(|i| Party::new(i, N, T, &mut rng)).collect();
    let A: Vec<PolyCommitment> = parties
        .iter()
        .map(|p| p.get_poly_commitment(&mut rng))
        .collect();
    let B: Vec<Vec<PublicNonce>> = parties
        .iter_mut()
        .map(|p| p.gen_nonces(num_nonces, &mut rng))
        .collect();
    let (total_compute_secret_time, total_secret_distribution_bandwidth) =
        distribute(&mut parties, &A, &B);

    let mut sig_agg = SignatureAggregator::new(N, T, A, B);

    let mut total_sig_time = 0;
    let mut total_party_sig_time = 0;
    let mut total_sig_bandwidth = 0;
    let mut total_nonce_distribution_bandwidth = 0;

    for sig_ct in 0..num_sigs {
        let msg = "It was many and many a year ago".to_string();
        let signers = select_parties(N, T, &mut rng);
        let nonce_ctr = sig_agg.get_nonce_ctr();
        let party_sig_start = time::Instant::now();
        let sig_shares = collect_signatures(&parties, &signers, nonce_ctr, &msg);
        let party_sig_time = party_sig_start.elapsed();
        let sig_start = time::Instant::now();
        let sig = sig_agg.sign(&msg, &sig_shares, &signers);
        let sig_time = sig_start.elapsed();

        total_party_sig_time += party_sig_time.as_micros();
        total_sig_time += sig_time.as_micros();
        total_sig_bandwidth += serialized_size(&sig_shares);

        println!("Signature (R,z) = \n({},{})", sig.R, sig.z);
        assert!(sig.verify(&sig_agg.key, &msg));

        // this resets one party's nonces assuming it went down and needed to regenerate
        if sig_ct == 3 {
            let reset_party = 2;
            println!("Resetting nonce for party {}", reset_party);
            reset_nonce(
                &mut parties,
                &mut sig_agg,
                reset_party,
                num_nonces,
                &mut rng,
            );
        }

        if sig_agg.get_nonce_ctr() == num_nonces as usize {
            println!("Everyone's nonces were refilled.");
            let B: Vec<Vec<PublicNonce>> = parties
                .iter_mut()
                .map(|p| p.gen_nonces(num_nonces, &mut rng))
                .collect();

            total_nonce_distribution_bandwidth += serialized_size(&B) * parties.len();

            for p in &mut parties {
                p.set_group_nonces(B.clone());
            }
            sig_agg.set_group_nonces(B.clone());
        }
    }
    println!("With {} parties and {} signers:", N, T);
    println!(
        "{} party secrets in {} us ({} us/secret)",
        N,
        total_compute_secret_time,
        total_compute_secret_time / (N as u128)
    );
    println!(
        "{} party signatures in {} us ({} us/sig)",
        num_sigs * T as u32,
        total_party_sig_time,
        total_party_sig_time / (num_sigs * (T as u32)) as u128
    );
    println!(
        "{} signatures in {} us ({} us/sig)",
        num_sigs,
        total_sig_time,
        total_sig_time / num_sigs as u128
    );

    println!("");
    println!(
        "Bandwidth usage\n  Secret distribution: {}\n  Nonce distribution: {}\n  Signing: {}",
        total_secret_distribution_bandwidth,
        total_nonce_distribution_bandwidth,
        total_sig_bandwidth
    );
}
