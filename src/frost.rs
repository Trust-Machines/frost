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
    pub A: Vec<Point>,
}

impl Share {
    pub fn verify(&self) -> bool {
        self.id.verify(&self.A[0])
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

// TODO: Remove public key from here
// The SA should get that as usual
pub struct SignatureShare {
    pub id: Scalar,
    pub z_i: Scalar,
    pub public_key: Point,
}

#[allow(non_snake_case)]
fn compute_binding(id: &Scalar, B: &Vec<PublicNonce>, msg: &String) -> Scalar {
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
fn compute_challenge(publicKey: &Point, R: &Point, msg: &String) -> Scalar {
    let mut hasher = Sha3_256::new();

    hasher.update(publicKey.compress().as_bytes());
    hasher.update(R.compress().as_bytes());
    hasher.update(msg.as_bytes());

    hash_to_scalar(&mut hasher)
}

fn lambda(i: &Scalar, indices: &Vec<usize>) -> Scalar {
    let mut lambda = Scalar::one();
    for p in indices {
        let id = Scalar::from((p + 1) as u32);
        if i != &id {
            lambda *= &id / (&id - i);
        }
    }
    lambda
}

// Is this the best way to return these values?
// TODO: this fn needs a better name
#[allow(non_snake_case)]
fn get_B_rho_R_vec(
    signers: &Vec<usize>,
    B: &Vec<Vec<PublicNonce>>,
    index: usize,
    msg: &String,
) -> (Vec<PublicNonce>, Vec<Point>, Point) {
    let B = signers.iter().map(|&i| B[i][index].clone()).collect();
    let rho: Vec<Scalar> = signers
        .iter()
        .map(|&i| compute_binding(&Scalar::from((i + 1) as u32), &B, &msg))
        .collect();
    let R_vec: Vec<Point> = (0..B.len()).map(|i| &B[i].D + &rho[i] * &B[i].E).collect();
    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (B, R_vec, R)
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Party {
    pub id: Scalar,
    pub public_key: Point,
    n: usize,
    _t: usize,
    f: Polynomial<Scalar>,
    shares: Vec<Share2>, // received from other parties
    private_key: Scalar,
    group_key: Point,
    nonces: Vec<Nonce>,
    B: Vec<Vec<PublicNonce>>, // received from other parties
}

impl Party {
    #[allow(non_snake_case)]
    pub fn new<RNG: RngCore + CryptoRng>(id: &Scalar, n: usize, t: usize, rng: &mut RNG) -> Self {
        Self {
            id: *id,
            n: n,
            _t: t,
            f: VSS::random_poly(t - 1, rng),
            shares: Vec::new(),
            private_key: Scalar::zero(),
            public_key: Point::zero(),
            group_key: Point::zero(),
            nonces: Vec::new(),
            B: Vec::new(),
        }
    }

    pub fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        num_nonces: u32,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        self.nonces = (0..num_nonces)
            .map(|_| Nonce {
                d: Scalar::random(rng),
                e: Scalar::random(rng),
            })
            .collect();
        self.nonces.iter().map(|n| PublicNonce::from(n)).collect()
    }

    #[allow(non_snake_case)]
    pub fn receive_nonces(&mut self, B: Vec<Vec<PublicNonce>>) {
        self.B = B;
    }

    #[allow(non_snake_case)]
    pub fn get_share<RNG: RngCore + CryptoRng>(&self, rng: &mut RNG) -> Share {
        Share {
            id: ID::new(&self.id, &self.f.data()[0], rng),
            A: (0..self.f.data().len())
                .map(|i| &self.f.data()[i] * G)
                .collect(),
        }
    }

    pub fn get_share2(&self, id: Scalar) -> Share2 {
        Share2 {
            i: id,
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

    // TODO: Maybe this should be private? If receive_share is keeping track
    // of which it receives, then this could be called when it has N shares from unique ids
    pub fn compute_secret(&mut self) {
        self.private_key = self.f.eval(self.id);
        // TODO: check that there is exactly one share from each other party
        for share in &self.shares {
            self.private_key += &share.f_i;
        }
        self.public_key = self.private_key * G;
        println!("Party {} secret {}", self.id, self.private_key);
    }

    #[allow(non_snake_case)]
    pub fn set_group_key(&mut self, A: &Vec<Share>) {
        assert!(A.len() == self.n);
        for A_i in A {
            assert!(A_i.verify());
        }

        for A_i in A {
            self.group_key += &A_i.A[0].clone();
        }
    }

    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &String, signers: &Vec<usize>, nonce_index: usize) -> Scalar {
        let (B, _R_vec, R) = get_B_rho_R_vec(&signers, &self.B, nonce_index, &msg);
        let nonce = &self.nonces[nonce_index]; // TODO: needs to check that index exists
        let mut z = &nonce.d + &nonce.e * compute_binding(&self.id, &B, &msg);
        z += compute_challenge(&self.group_key, &R, &msg)
            * &self.private_key
            * lambda(&self.id, signers);
        z
    }
}

#[allow(non_snake_case)]
pub struct Signature {
    pub R: Point,
    pub z: Scalar,
}

impl Signature {
    // verify: R' = z * G + -c * publicKey, pass if R' == R
    #[allow(non_snake_case)]
    pub fn verify(&self, public_key: &Point, msg: &String) -> bool {
        let c = compute_challenge(&public_key, &self.R, &msg);
        let R = &self.z * G + (-c) * public_key;

        println!("Verification R = {}", R);

        R == self.R
    }
}

#[allow(non_snake_case)]
pub struct SignatureAggregator {
    pub N: usize,
    pub T: usize,
    pub A: Vec<Share>,            // outer vector is N-long, inner vector is T-long
    pub B: Vec<Vec<PublicNonce>>, // outer vector is N-long, inner vector is T-long
    pub key: Point,
    nonce_ctr: usize,
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

        let mut key = Point::new(); // TODO: Compute pub key from A
        for A_i in &A {
            key += &A_i.A[0];
        }
        println!("SA groupKey {}", key);

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
            key: key,
            nonce_ctr: 0,
            num_nonces: num_nonces,
        }
    }

    #[allow(non_snake_case)]
    pub fn sign(
        &mut self,
        msg: &String,
        sig_shares: &Vec<SignatureShare>,
        signers: &Vec<usize>,
    ) -> Signature {
        let (_B, R_vec, R) = get_B_rho_R_vec(&signers, &self.B, self.nonce_ctr, &msg);

        let mut z = Scalar::zero();
        let c = compute_challenge(&self.key, &R, &msg); // only needed for checking z_i
        for i in 0..signers.len() {
            let z_i = sig_shares[i].z_i;
            assert!(
                z_i * G
                    == R_vec[i]
                        + (lambda(&sig_shares[i].id, signers) * c * sig_shares[i].public_key)
            ); // TODO: This should return a list of bad parties.
            z += z_i;
        }
        self.update_nonce();

        Signature { R: R, z: z }
    }

    pub fn get_nonce_ctr(&self) -> usize {
        self.nonce_ctr
    }

    fn update_nonce(&mut self) {
        self.nonce_ctr += 1;
        if self.nonce_ctr == self.num_nonces {
            println!("Out of nonces! Need to generate new ones!");
            // TODO: Trigger another round of nonces generation & sharing B
            self.nonce_ctr = 0;
        }
    }
}
