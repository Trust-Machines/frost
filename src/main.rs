use num_traits::identities::Zero;
use polynomial::Polynomial;
use rand_core::{OsRng, RngCore};
use secp256k1_math::{point::Point, scalar::Scalar};
use std::{env, time};

mod frost;
mod schnorr;
mod util;
mod vss;

use frost::{Party, Share, Share2, Signature};

fn eval(p: &Polynomial<Point>, x: &Scalar) -> Point {
    let mut y = x.clone();
    let mut val = p.data()[0].clone();

    for i in 1..p.data().len() {
        val += &p.data()[i] * &y;
        y *= y;
    }

    val
}

#[allow(non_snake_case)]
fn main() {
    let args: Vec<String> = env::args().collect();
    let mut rng = OsRng::default();
    let N: usize = if args.len() > 1 {
	args[1].parse::<usize>().unwrap()
    } else {
	3
    };

    let T: usize = if args.len() > 2 {
	args[2].parse::<usize>().unwrap()
    } else {
	(N * 2) / 3
    };

    let mut parties: Vec<Party> = (0..N)
        .map(|n| Party::new(&Scalar::from((n + 1) as u32), T, &mut rng))
        .collect();
    let shares: Vec<Share> = parties.iter().map(|p| p.share(&mut rng)).collect();

    // everybody checks everybody's shares
    for share in &shares {
        assert!(share.verify());
    }

    let mut agg_params = Vec::new();
    for i in 0..T {
        let mut agg = Point::default();
        for share in &shares {
            agg += share.phi[i];
        }
        agg_params.push(agg);
    }
    let P: Polynomial<Point> = Polynomial::new(agg_params);

    let zero = eval(&P, &Scalar::zero());

    //let p = Polynomial::<Scalar>::lagrange(&xs, &ys).unwrap();
    //println!("P(0) = {}", zero);

    // compute aggregate public key Y

    let mut Y = Point::zero();
    for share in &shares {
        Y = Y + &share.phi[0];
    }

    println!("Aggregate public key Y = {}", Y);

    assert_eq!(zero, Y);
    
    // round2
    for i in 0..N {
        let party = parties[i].clone();
        for j in 0..N {
            let party2 = &mut parties[j];

            // party sends party2 the round2 share
            party2.send(Share2 {
                i: party2.id,
                f_i: party.f.eval(party2.id),
            });
        }
    }

    for party in &mut parties {
        party.compute_secret();
        //println!("Party {} secret {}", &party.id, &party.secret);
    }

    // choose a random list of T parties to sign
    let mut available_parties = parties;
    let mut signing_parties = Vec::new();
    while signing_parties.len() < T {
        let i = rng.next_u64() as usize % available_parties.len();
        signing_parties.push(available_parties[i].clone());
        available_parties.remove(i);
    }

    let msg = "It was many and many a year ago".to_string();

    let _S: Vec<Scalar> = signing_parties.iter().map(|p| p.id).collect();

    //let B: Vec<PublicNonce> = signing_parties.iter().map(|p:&mut Party| p.pop_nonce(&mut rng)).collect();

    let sig_start = time::Instant::now();
    let sig = Signature::new(&Y, &msg, &mut signing_parties, &mut rng);
    let sig_time = sig_start.elapsed();
    println!("Signing took {}us", sig_time.as_micros());
    println!("Signature R,z = \n{},{}", sig.R, sig.z);

    let ver_start = time::Instant::now();
    assert!(sig.verify(&Y, &msg));
    let ver_time = ver_start.elapsed();
    println!("Verifying took {}us", ver_time.as_micros());
}
