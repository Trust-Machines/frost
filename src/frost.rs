use num_traits::{One, Zero};
use polynomial::Polynomial;
use rand_core::{CryptoRng, RngCore};
use secp256k1_math::{
    point::{Point, G},
    scalar::Scalar,
};
use sha3::{Digest, Sha3_256};

use crate::schnorr::ID;
use crate::util::hash_to_scalar;
use crate::vss::VSS;

#[allow(non_snake_case)]
pub struct Share {
    pub id: ID,
    pub phi: Vec<Point>,
}

impl Share {
    pub fn verify(&self) -> bool {
        self.id.verify(&self.phi[0])
    }
}

#[derive(Clone)]
pub struct Share2 {
    pub i: Scalar,
    pub f_i: Scalar,
}

#[derive(Clone)]
pub struct Nonce {
    d: Scalar,
    e: Scalar,
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct PublicNonce {
    pub D: Point,
    pub E: Point,
}

impl PublicNonce {
    pub fn from(n: &Nonce) -> Self {
        Self {
            D: &n.d * G,
            E: &n.e * G,
        }
    }
}

// TODO: remove the pubs where they should be private
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Party {
    pub id: Scalar,
    f: Polynomial<Scalar>,
    shares: Vec<Share2>, // received from other parties
    secret: Scalar,
    pub nonces: Vec<Nonce>,
    pub Y: Point,
}

impl Party {
    pub fn new<RNG: RngCore + CryptoRng>(id: &Scalar, t: usize, rng: &mut RNG) -> Self {
        Self {
            id: *id,
            f: VSS::random_poly(t - 1, rng),
            shares: Vec::new(),
            secret: Scalar::zero(),
            nonces: Vec::new(),
            Y: Point::zero(),
        }
    }

    pub fn gen_share<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> Share {
        Share {
            id: ID::new(&self.id, &self.f.data()[0], rng),
            phi: (0..self.f.data().len())
                .map(|i| &self.f.data()[i] * G)
                .collect(),
        }
    }

    pub fn gen_share2(&self, id: Scalar) -> Share2 {
        Share2 {
            i: self.id,
            f_i: self.f.eval(id),
        }
    }

    // TODO: keep track of IDs to ensure each is included once
    // TODO: Either automatically compute_secret when N shares arrive
    // or trigger it when done sharing and bark if there aren't N
    pub fn receive_share(&mut self, share: Share2) {
        //println!("id: {} received: {} {}", self.id, i, f_i);
        // TODO: Verify against public commitment of A
        // TODO: Perhaps check A proof here as well?
        self.shares.push(share);
    }

    pub fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        k: usize,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        self.nonces = (0..k)
            .map(|_| Nonce {
                d: Scalar::random(rng),
                e: Scalar::random(rng),
            })
            .collect();

        self.nonces.iter().map(|n| PublicNonce::from(n)).collect()
    }

    pub fn gen_secret(&mut self) {
        //self.secret = self.f.eval(self.id);
        for share in &self.shares {
            self.secret += &share.f_i;
        }

        self.Y = self.secret * G;
    }

    #[allow(non_snake_case)]
    pub fn gen_binding(id: &Scalar, B: &Vec<PublicNonce>, msg: &String) -> Scalar {
        let mut hasher = Sha3_256::new();

        hasher.update(id.as_bytes());
        for b in B {
            hasher.update(b.D.compress().as_bytes());
            hasher.update(b.E.compress().as_bytes());
        }
        hasher.update(msg.as_bytes());

        hash_to_scalar(&mut hasher)
    }

    #[allow(non_snake_case)]
    pub fn gen_lambda(i: &Scalar, S: &Vec<Scalar>) -> Scalar {
        let mut lambda = Scalar::one();

        for id in S {
            if i != id {
                lambda *= id / (id - i);
            }
        }

        lambda
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &self,
        Y: &Point,
        R: &Point,
        msg: &String,
        rho: &Scalar,
        lambda: &Scalar,
        nonce_index: usize,
    ) -> Scalar {
        let nonce = &self.nonces[nonce_index];
        let c = Signature::gen_challenge(Y, R, msg);
        nonce.d + rho * &nonce.e + c * lambda * &self.secret
    }
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct PublicParty {
    pub id: Scalar,
    pub Y: Point,
    pub nonces: Vec<Nonce>,
    pub rho: Scalar,
    pub z: Scalar,
}

impl PublicParty {
    pub fn from(p: &Party) -> Self {
        Self {
            id: p.id,
            Y: p.Y,
            nonces: p.nonces.clone(),
            rho: Scalar::zero(),
            z: Scalar::zero(),
        }
    }
}

#[allow(non_snake_case)]
pub struct Signature {
    pub R: Point,
    pub z: Scalar,
}

impl Signature {
    #[allow(non_snake_case)]
    pub fn new(
        Y: &Point,
        R: &Point,
        msg: &String,
        B: &Vec<PublicNonce>,
        S: &Vec<Scalar>,
        Yi: &Vec<Point>,
        rho: &Vec<Scalar>,
        sigs: &Vec<Scalar>,
    ) -> Self {
        let mut z = Scalar::zero();
        for (i, id) in S.iter().enumerate() {
            let lambda = Party::gen_lambda(&id, S);
            let z_i = sigs[i];

            // verify each z_i to identify malicious byzantine actors
            //assert!(
            if !Self::verify_party_signature(&z_i, &B[i], &Y, &rho[i], &R, &msg, &lambda, &Yi[i]) {
                println!("Party signature failed verification");
            }

            z += z_i;
        }

        Self { R: R.clone(), z: z }
    }

    #[allow(non_snake_case)]
    pub fn gen_challenge(Y: &Point, R: &Point, msg: &String) -> Scalar {
        let mut hasher = Sha3_256::new();

        hasher.update(Y.compress().as_bytes());
        hasher.update(R.compress().as_bytes());
        hasher.update(msg.as_bytes());

        hash_to_scalar(&mut hasher)
    }

    #[allow(non_snake_case)]
    pub fn verify_party_signature(
        z: &Scalar,
        nonce: &PublicNonce,
        Y: &Point,
        rho: &Scalar,
        R: &Point,
        msg: &String,
        lambda: &Scalar,
        Yi: &Point,
    ) -> bool {
        let c = Self::gen_challenge(Y, R, msg);

        z * G == (nonce.D + rho * nonce.E + (c * lambda * Yi))
    }

    // verify: R' = z * G + -c * Y, pass if R' == R
    #[allow(non_snake_case)]
    pub fn verify(&self, Y: &Point, msg: &String) -> bool {
        let c = Self::gen_challenge(Y, &self.R, msg);
        let R = &self.z * G + (-c) * Y;

        println!("Verification R = \n{}", R);
        R == self.R
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub N: usize,
    pub T: usize,
    pub A: Vec<Share>,
    pub B: Vec<Vec<PublicNonce>>, // outer vector is N-long, inner vector is T-long
    pub Y: Point,
    pub nonce_ctr: usize,
    num_nonces: usize,
}

impl SignatureAggregator {
    #[allow(non_snake_case)]
    pub fn new(N: usize, T: usize, A: Vec<Share>, B: Vec<Vec<PublicNonce>>) -> Self {
        // TODO: How should we handle bad As?
        assert!(A.len() == N);
        for A_i in &A {
            assert!(A_i.verify());
        }

        let mut Y = Point::new(); // TODO: Compute pub key from A
        for A_i in &A {
            Y += &A_i.phi[0];
        }

        assert!(B.len() == N);
        let num_nonces = B[0].len();
        for b in &B {
            assert!(num_nonces == b.len());
        }
        // TODO: Check that each B_i is len num_nonces?

        Self {
            N: N,
            T: T,
            A: A,
            B: B,
            Y: Y,
            nonce_ctr: 0,
            num_nonces: num_nonces,
        }
    }

    pub fn get_nonces(&self, signers: &Vec<usize>) -> Vec<PublicNonce> {
        signers
            .iter()
            .map(|&i| self.B[i][self.nonce_ctr].clone())
            .collect()
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &String,
        parties: &Vec<PublicParty>,
        signers: &Vec<usize>,
    ) -> Signature {
        let B = self.get_nonces(signers);
        let rho: Vec<Scalar> = signers
            .iter()
            .map(|i| Party::gen_binding(&parties[*i].id, &B, &msg))
            .collect();
        let R_vec: Vec<Point> = (0..B.len()).map(|i| &B[i].D + &rho[i] * &B[i].E).collect();
        let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
        let S: Vec<Scalar> = signers.iter().map(|x| parties[*x].id).collect();
        let Yi: Vec<Point> = signers.iter().map(|x| parties[*x].Y).collect();
        let Z: Vec<Scalar> = signers.iter().map(|x| parties[*x].z).collect();

        self.update_nonce();

        Signature::new(&self.Y, &R, &msg, &B, &S, &Yi, &rho, &Z)
    }

    fn update_nonce(&mut self) {
        self.nonce_ctr += 1;
        if self.nonce_ctr == self.num_nonces {
            println!("Out of nonces!");
            // TODO: Trigger another collection of Bs
            self.nonce_ctr = 0;
        }
    }
}
