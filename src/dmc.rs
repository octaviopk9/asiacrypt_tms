use blake3::{Hash, Hasher};
use blstrs::*;
use crypto_bigint::{Encoding, U256};
use ff::Field;
use group::Group;

/// Implementation of mercurial signature using the bls12-381 elliptic curve
#[derive(Debug, Clone, Copy)]
pub struct MercurialSignatureScheme {
    _p: U256, // order of the groups, p
    l: usize, // lengths of keys and messages
    p_1: G1Projective,
    p_2: G2Projective,
}

/// Mercurial signatures are computed in the signing algorithm for a given message
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MercurialSignature {
    pub Z: G1Projective,
    pub Y_1: G1Projective,
    pub Y_2: G2Projective,
}

/// Computes a random number in Zp\{0} mod q in potentially variable time (insignificant probability)
/// Retry as long as it equals 0, but it has insignificant probability each time
pub fn random_z_star_p() -> Scalar {
    let rng = rand::thread_rng();
    let mut random = Scalar::random(rng);
    while !random.is_zero().unwrap_u8() == 0 {
        let rng = rand::thread_rng();
        random = Scalar::random(rng);
    }
    random
}

/// Computes a random number, zero being a possibility
pub fn random_z_p() -> Scalar {
    let rng = rand::thread_rng();
    Scalar::random(rng)
}

impl MercurialSignatureScheme {
    /// This structure only contains elements necessary for computations, l is the maximum length
    /// possible of messages
    #[allow(dead_code)]
    pub fn new(el: usize) -> MercurialSignatureScheme {
        MercurialSignatureScheme {
            _p: U256::from_be_hex(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            ),
            l: el,
            p_1: G1Projective::generator(),
            p_2: G2Projective::generator(),
        }
    }

    /// Key generation of the signing party
    #[allow(dead_code)]
    pub fn key_gen(&self) -> (Vec<Scalar>, Vec<G2Projective>) {
        let mut pk: Vec<G2Projective> = Vec::with_capacity(self.l);
        let mut sk: Vec<Scalar> = Vec::with_capacity(self.l);

        for _ in 0..(self.l as u64) {
            let x_i = random_z_star_p();
            let p_x = self.p_2 * x_i;
            pk.push(p_x);
            sk.push(x_i);
        }
        (sk, pk)
    }

    /// Generate a vector of l elements in G1, chosen randomly
    /// Doesn't correspond to a part of the scheme but it is useful to test the Sign algorithm
    #[allow(dead_code)]
    pub fn random_message(&self) -> Vec<G1Projective> {
        let mut message: Vec<G1Projective> = Vec::with_capacity(self.l);
        for _ in 0..(self.l as u64) {
            message.push(self.p_1 * random_z_star_p());
        }
        message
    }

    /// Signing algorithm. The message signed is a vector of elements in G1
    #[allow(dead_code, non_snake_case, non_camel_case_types)]
    pub fn sign(&self, sk: &[Scalar], message: &[G1Projective]) -> MercurialSignature {
        let y = random_z_star_p();
        let inv_y = y.invert().unwrap(); // outputs the multiplicative inverse of y
        let mut Z = message[0] * sk[0]; // To instantiate Z properly
        if self.l > 1 {
            Z += G1Projective::multi_exp(&message[1..], &sk[1..]);
        }
        Z *= y;
        let Y_1 = self.p_1 * inv_y;
        let Y_2 = self.p_2 * inv_y;
        MercurialSignature { Z, Y_1, Y_2 }
    }

    /// Verification algorithm. The message signed is a vector of elements in G1
    #[allow(dead_code)]
    pub fn verify(
        &self,
        pk: &[G2Projective],
        message: &[G1Projective],
        sigma: &MercurialSignature,
    ) -> bool {
        let mut pair_1 = pairing(&G1Affine::from(message[0]), &G2Affine::from(pk[0]));
        for i in 1..self.l {
            pair_1 += pairing(&G1Affine::from(message[i]), &G2Affine::from(pk[i]));
        }
        let pair_2 = pairing(&G1Affine::from(sigma.Z), &G2Affine::from(sigma.Y_2));
        let pair_3 = pairing(&G1Affine::from(sigma.Y_1), &G2Affine::from(self.p_2));
        let pair_4 = pairing(&G1Affine::from(self.p_1), &G2Affine::from(sigma.Y_2));

        pair_1.eq(&pair_2) && pair_3.eq(&pair_4)
    }

    /// Randomizes the secret key using rho, an element of Zp
    #[allow(dead_code)]
    pub fn convert_sk(sk: &Vec<Scalar>, rho: &Scalar) -> Vec<Scalar> {
        let mut sk_converted: Vec<Scalar> = Vec::with_capacity(sk.len());
        for &val in sk {
            sk_converted.push(rho * val);
        }
        sk_converted
    }

    /// Randomizes the public key using rho, an element of Zp
    #[allow(dead_code)]
    pub fn convert_pk(pk: &Vec<G2Projective>, rho: &Scalar) -> Vec<G2Projective> {
        let mut pk_converted: Vec<G2Projective> = Vec::with_capacity(pk.len());
        for &val in pk {
            pk_converted.push(val * rho);
        }
        pk_converted
    }

    /// Randomizes the generated signature using the same rho
    #[allow(dead_code)]
    pub fn convert_sig(sigma: &MercurialSignature, rho: &Scalar) -> MercurialSignature {
        let psi = random_z_star_p();
        let psi_inv = psi.invert().unwrap(); //Multiplicative invert of psi
        let rand = psi * rho;
        let new_z = sigma.Z * rand;
        let new_y = sigma.Y_1 * psi_inv;
        let new_y_hat = sigma.Y_2 * psi_inv;
        MercurialSignature {
            Z: new_z,
            Y_1: new_y,
            Y_2: new_y_hat,
        }
    }

    /// Randomizes consistently the signature and the signed message so the signature verification
    /// holds for the randomized message
    #[allow(dead_code)]
    pub fn change_rep(
        message: &Vec<G1Projective>,
        sigma: &MercurialSignature,
        mu: &Scalar,
        rho: &Scalar,
    ) -> (Vec<G1Projective>, MercurialSignature) {
        let psi = random_z_star_p();
        let psi_inv = psi.invert().unwrap(); // multiplicative inverse of psi
        let mut new_message: Vec<G1Projective> = Vec::with_capacity(message.len());
        for &element in message {
            new_message.push(element * mu);
        }
        let rand1 = psi * mu * rho;
        let new_z = sigma.Z * rand1; // psi * mu * rho
        let new_y = sigma.Y_1 * psi_inv;
        let new_y_hat = sigma.Y_2 * psi_inv;
        let new_signature = MercurialSignature {
            Z: new_z,
            Y_1: new_y,
            Y_2: new_y_hat,
        };
        (new_message, new_signature)
    }
}

/// Implementation of distributed mercurial signature using the bls12-381 elliptic curve
#[derive(Debug, Clone, Copy)]
pub struct DistributedMercurialSignatureScheme {
    _p: U256,          // order of the groups, p
    l: usize,          // lengths of keys and messages
    p_1: G1Projective, // in the paper, generator of G1: P
    p_2: G2Projective, // in the paper, generator of G2: \hat P
}

/// Distribute mercurial signatures are also computed in the signing algorithm for a given message
#[allow(non_snake_case, non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedMercurialSignature {
    pub Z: G1Projective,
    pub Y_1: G1Projective, // in the paper, Y
    pub Y_2: G2Projective, // in the paper, \hat Y
}

/// The hash function outputs elements over 256 bits. However, scalars are defined
/// over Zp with p << 2^256. Therefore we need to apply a modulus to the digest to be sure that
/// we have a canonical input every time.
/// We use the crate crypto bigint : we transform the digest into a bigint, apply modulus on the
/// bigint and generate a scalar from the little endian bitwise representation of the bigint.
pub fn digest_into_scalar(value_before_modulus: Hash) -> Scalar {
    let p = U256::from_be_hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let bigint: U256 = U256::from_be_slice(value_before_modulus.as_bytes());
    let value_mod_p: U256 = bigint.reduce(&p).unwrap();
    if U256::is_zero(&value_mod_p).unwrap_u8() == 1 {
        return Scalar::from_bytes_le(&bigint.to_le_bytes()).unwrap();
    }
    let resulting_scalar: Scalar = Scalar::from_bytes_le(&value_mod_p.to_le_bytes()).unwrap();
    resulting_scalar
}

/// 2-party Multi-Party Computation protocol for the generation of Distribute Mercurial Signatures
impl DistributedMercurialSignatureScheme {
    /// This structure only contains elements necessary for computations, l is the maximum length
    /// possible of messages
    pub fn new(el: usize) -> DistributedMercurialSignatureScheme {
        DistributedMercurialSignatureScheme {
            _p: U256::from_be_hex(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            ),
            l: el,
            p_1: G1Projective::generator(),
            p_2: G2Projective::generator(),
        }
    }

    /// Key generation of the signing 2 parties
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn key_gen(&self) -> (Vec<Vec<Scalar>>, Vec<Vec<G2Projective>>, Vec<G2Projective>) {
        // sk_0 and sk_1 are the shares for each of the two parties.
        // sk wraps the two shares.
        let mut sk_0: Vec<Scalar> = Vec::with_capacity(self.l); // in the paper, \vec sk_0 = (x_0^1,..,x_0^l)
        let mut sk_1: Vec<Scalar> = Vec::with_capacity(self.l); // in the paper, \vec sk_1 = (x_1^1,..,x_1^l)

        // lpk_0 and lpk_1 are the (published) local verification keys for each of the two parties, just for using ZKPoK.
        // lpk wraps the two local verification keys.
        let mut lpk_0: Vec<G2Projective> = Vec::with_capacity(self.l); // in the paper, \vec pk_0 = (P^{x_0^1},..,P^{x_0^l})
        let mut lpk_1: Vec<G2Projective> = Vec::with_capacity(self.l); // in the paper, \vec pk_1 = (P^{x_1^1},..,P^{x_1^l})

        // pk is the verification key.
        let mut pk: Vec<G2Projective> = Vec::with_capacity(self.l); // in the paper, pk = (P^{x_0^1 + x_1^1},..,P^{x_0^l + x_1^l})

        for _ in 0..(self.l as u64) {
            let x_0_i = random_z_star_p();
            let x_1_i = random_z_star_p();
            let pk_0_i = self.p_2 * x_0_i;
            let pk_1_i = self.p_2 * x_1_i;
            let X_i = self.p_2 * (x_0_i + x_1_i);
            sk_0.push(x_0_i);
            sk_1.push(x_1_i);
            lpk_0.push(pk_0_i);
            lpk_1.push(pk_1_i);
            pk.push(X_i);
        }

        (vec![sk_0, sk_1], vec![lpk_0, lpk_1], pk)
    }

    /// Generate a vector of l elements in G1, chosen randomly
    /// Doesn't correspond to a part of the scheme but it is useful to test the Sign algorithm
    pub fn random_message(&self) -> Vec<G1Projective> {
        let mut message: Vec<G1Projective> = Vec::with_capacity(self.l);
        for _ in 0..(self.l as u64) {
            let random_scalar = random_z_star_p();
            let element_m = self.p_1 * random_scalar;
            message.push(element_m);
        }
        message
    }

    /// 2-party interactive signing algorithm.
    /// The message signed is a vector of elements in G1
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign(
        &self,
        sk: &[Vec<Scalar>], // signing key
        message: &Vec<G1Projective>,
        lpk: &[Vec<G2Projective>],
    ) -> DistributedMercurialSignature {
        // In each of steps, if ZKPoK fails, the protocol stops and returns a failed result
        let failed_res = DistributedMercurialSignature {
            Z: G1Projective::identity(),
            Y_1: G1Projective::identity(),
            Y_2: G2Projective::identity(),
        };

        // Hash function is generated here
        // Each party uses the same hash function by cloning
        let hasher = blake3::Hasher::new();

        // Round 1 of Party 0
        let (
            Y_1_0,    // in the paper, Y_0
            Y_2_0,    // in the paper, \hat Y_0
            pi_r1_p0, // in the paper, \pi^{(1)}_0
            y_0, // in the paper, party 0 doesn't pass y_0 (just for holding in party 0 to use in the next round)
        ) = self.sign_round1_P0(&hasher);
        if !pi_r1_p0 {
            println!("==== Round 1 of P0 failed ====");
            return failed_res;
        }

        // Round 1 of Party 1
        let (
            Z_1,
            pi_r1_p1, // in the paper, \pi^{(1)}_1
            r, // in the paper, party 1 doesn't pass r (just for holding in party 1 to use in the next round)
            y_1, // in the paper, party 1 doesn't pass y_1 (just for holding in party 1 to use in the next round)
            Y_1, // Y_1 isn't passed, but published one of the elements of the signature
            Y_2, // Y_2 isn't passed, but published one of the elements of the signature
        ) = self.sign_round1_P1(&sk[1], message, &Y_1_0, &Y_2_0, &lpk[1], &hasher); // Y and \hat Y are computed in the next round
        if !pi_r1_p1 {
            println!("==== Round 1 of P1 failed ====");
            return failed_res;
        }

        // Round 2 of Party 0
        let (
            Z_0,
            pi_r0_p2, // in the paper, \pi^{(2)}_0
        ) = self.sign_round2_P0(&sk[0], message, &Z_1, &y_0, &Y_1_0, &lpk[0], &hasher);
        if !pi_r0_p2 {
            println!("==== Round 2 of P0 failed ====");
            return failed_res;
        }

        // Round 2 of Party 1
        let (
            sigma,
            p1_r1_p2, // in the paper, \pi^{(2)}_1
        ) = self.sign_round2_P1(&Z_0, &r, &Y_1_0, y_1, &Y_1, &Y_2, &hasher);
        if !p1_r1_p2 {
            println!("==== Round 2 of P1 failed ====");
            return failed_res;
        }
        sigma
    }

    /// 2-party interactive signing algorithm. Round 1 of P0
    /// Commit to the random value y_0
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign_round1_P0(&self, hasher: &Hasher) -> (G1Projective, G2Projective, bool, Scalar) {
        let y_0 = random_z_star_p();
        let inv_y_0 = y_0.invert().unwrap(); // inv_y_0 means 1/y_0
        let Y_1_0 = self.p_1 * inv_y_0;
        let Y_2_0 = self.p_2 * inv_y_0;

        // Execute the ZKPoK protocol between Party 0 (Prover) and Party 1 (Verifier)
        let (A_1, A_2, c, q) = self.zkpok_pi_r1_p0_prover(&Y_1_0, &Y_2_0, &y_0, hasher);
        let pi_r1_p0 = self.zkpok_pi_r1_p0_verifier(&Y_1_0, &Y_2_0, &A_1, &A_2, &c, &q);

        (Y_1_0, Y_2_0, pi_r1_p0, y_0) // y_0 is needed as the argument of the next round (only used by P0)
    }

    /// Prover is Party 0
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn zkpok_pi_r1_p0_prover(
        &self,
        Y_1_0: &G1Projective,
        Y_2_0: &G2Projective,
        y_0: &Scalar,
        hasher: &Hasher,
    ) -> (G1Projective, G2Projective, Scalar, Scalar) {
        let a = random_z_star_p();
        let A_1 = Y_1_0 * a; // in the paper, A_1 means commitment A in G1
        let A_2 = Y_2_0 * a; // in the paper, A_2 means commitment \hat A in G2

        // Use hash fuction instead of receiving the challenge from the verifier
        let c = self.hash_secret_and_statement_pi_r1_p0(hasher, &A_1, &A_2, Y_1_0, Y_2_0);

        let q = a - c * y_0;
        (A_1, A_2, c, q)
    }

    /// Hash function uses not only the commitment but also the statement as input
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn hash_secret_and_statement_pi_r1_p0(
        &self,
        hasher: &Hasher,
        A_1: &G1Projective,
        A_2: &G2Projective,
        Y_0: &G1Projective,
        Y_2_0: &G2Projective,
    ) -> Scalar {
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G2Affine::from(A_2).to_compressed());
        h.update(&G1Affine::from(Y_0).to_compressed());
        h.update(&G2Affine::from(Y_2_0).to_compressed());
        digest_into_scalar(h.finalize())
    }

    /// Verifier is Party 1
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn zkpok_pi_r1_p0_verifier(
        &self,
        Y_1_0: &G1Projective,
        Y_2_0: &G2Projective,
        A_1: &G1Projective,
        A_2: &G2Projective,
        c: &Scalar,
        q: &Scalar,
    ) -> bool {
        A_1.eq(&(Y_1_0 * q + self.p_1 * c)) && A_2.eq(&(Y_2_0 * q + self.p_2 * c))
    }

    /// 2-party interactive signing algorithm. Round 2 of P1
    /// Compute the partial signature and blind it with Y_0 and r
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign_round1_P1(
        &self,
        sk_1: &[Scalar],
        message: &Vec<G1Projective>,
        Y_1_0: &G1Projective,
        Y_2_0: &G2Projective,
        lpk_1: &[G2Projective],
        hasher: &Hasher,
    ) -> (
        G1Projective,
        bool,
        Scalar,
        Scalar,
        G1Projective,
        G2Projective,
    ) {
        let r = random_z_p();
        let y_1 = random_z_star_p();
        let Z_1 = Y_1_0 * r + G1Projective::multi_exp(message.as_slice(), sk_1);

        let inv_y_1 = y_1.invert().unwrap(); // inv_y_1 means 1/y_1
        let Y_1 = Y_1_0 * inv_y_1;
        let Y_2 = Y_2_0 * inv_y_1;

        // Execute the ZKPoK protocol between Party 1 (Prover) and Party 0 (Verifier)
        let (A_1, A_2, c, q) =
            self.zkpok_pi_r1_p1_prover(&Z_1, Y_1_0, message, lpk_1, sk_1, &r, hasher);
        let pi_r1_p1 =
            self.zkpok_pi_r1_p1_verifier(&Z_1, Y_1_0, message, lpk_1, &A_1, &A_2, &c, &q);

        (Z_1, pi_r1_p1, r, y_1, Y_1, Y_2) // r and y_1 are secret but needed as the argument of the next round
    }

    /// Prover is Party 1
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zkpok_pi_r1_p1_prover(
        &self,
        Z_1: &G1Projective,
        Y_1_0: &G1Projective,
        message: &Vec<G1Projective>,
        lpk_1: &[G2Projective],
        sk_1: &[Scalar],
        r: &Scalar,
        hasher: &Hasher,
    ) -> (G1Projective, Vec<G2Projective>, Scalar, Vec<Scalar>) {
        let mut a: Vec<Scalar> = Vec::with_capacity(self.l + 1);
        for _ in 0..(self.l + 1) {
            a.push(random_z_star_p());
        }

        // in the paper, A_1 wraps commitment A_0 in G1
        let A_1 = Y_1_0 * a[0] + G1Projective::multi_exp(message.as_slice(), &a[1..]);

        // in the paper, A_2 wraps commitments \hat A_1, \hat A_2, ..., \hat A_l in G2
        let mut A_2: Vec<G2Projective> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            A_2.push(self.p_2 * a[i + 1]);
        }

        // Use hash fuction instead of receiving the challenge from the verifier
        let c = self.hash_secret_and_statement_pi_r1_p1(hasher, &A_1, &A_2, Z_1, lpk_1, message);

        // q wraps q_0 q_1, ..., q_l
        let mut q: Vec<Scalar> = Vec::with_capacity(self.l + 1);
        q.push(a[0] - c * r);
        for i in 1..(self.l + 1) {
            q.push(a[i] - c * sk_1[i - 1]);
        }

        (A_1, A_2, c, q)
    }

    /// Hash function uses not only the commitment but also the statement and message as input
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn hash_secret_and_statement_pi_r1_p1(
        &self,
        hasher: &Hasher,
        A_1: &G1Projective,
        A_2: &[G2Projective],
        Z_1: &G1Projective,
        lpk_1: &[G2Projective],
        message: &[G1Projective],
    ) -> Scalar {
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        for alpha in A_2.iter().take(self.l) {
            h.update(&G2Affine::from(alpha).to_compressed());
        }
        h.update(&G1Affine::from(Z_1).to_compressed());
        for key in lpk_1.iter().take(self.l) {
            h.update(&G2Affine::from(key).to_compressed());
        }
        for msg in message.iter().take(self.l) {
            h.update(&G1Affine::from(msg).to_compressed());
        }
        digest_into_scalar(h.finalize())
    }

    /// Verifier is Party 0
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zkpok_pi_r1_p1_verifier(
        &self,
        Z_1: &G1Projective,
        Y_1_0: &G1Projective,
        message: &Vec<G1Projective>,
        lpk_1: &[G2Projective],
        A_1: &G1Projective,
        A_2: &Vec<G2Projective>,
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        let mut B_2: Vec<G2Projective> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            B_2.push(self.p_2 * q[i + 1] + lpk_1[i] * c);
        }

        A_1.eq(&(Y_1_0 * q[0] + G1Projective::multi_exp(message.as_slice(), &q[1..]) + Z_1 * c))
            && A_2.eq(&B_2)
    }

    /// 2-party interactive signing algorithm. Round 2 of P0
    /// Compute the partial signature and randomize it with commited value y_0
    /// The partial signature keeps being blinded with Y_0 and the random value r
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round2_P0(
        &self,
        sk_0: &Vec<Scalar>,
        message: &Vec<G1Projective>,
        Z_1: &G1Projective,
        y_0: &Scalar,
        Y_1_0: &G1Projective,
        lpk_0: &[G2Projective],
        hasher: &Hasher,
    ) -> (G1Projective, bool) {
        let Z_0 = (*Z_1 + G1Projective::multi_exp(message.as_slice(), sk_0.as_slice())) * y_0;

        // Execute the ZKPoK protocol between Party 0 (Prover) and Party 1 (Verifier)
        let y_prm_0 = y_0.invert().unwrap(); // y_prm_0 means 1/y_0
        let (A_1, A_2, c, q) =
            self.zkpok_pi_r2_p0_prover(Z_1, &Z_0, Y_1_0, &y_prm_0, message, lpk_0, sk_0, hasher);
        let pi_r2_p0 =
            self.zkpok_pi_r2_p0_verifier(&Z_0, Z_1, Y_1_0, message, lpk_0, &A_1, &A_2, &c, &q);

        (Z_0, pi_r2_p0)
    }

    /// Prover is Party 0
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zkpok_pi_r2_p0_prover(
        &self,
        Z_1: &G1Projective,
        Z_0: &G1Projective,
        Y_1_0: &G1Projective,
        y_prm_0: &Scalar, // in the paper, y'_0
        message: &Vec<G1Projective>,
        lpk_0: &[G2Projective],
        sk_0: &[Scalar],
        hasher: &Hasher,
    ) -> (Vec<G1Projective>, Vec<G2Projective>, Scalar, Vec<Scalar>) {
        let mut a: Vec<Scalar> = Vec::with_capacity(self.l + 1);
        let mut minus_a: Vec<Scalar> = Vec::with_capacity(self.l + 1);
        for _ in 0..(self.l + 1) {
            let a_i = random_z_star_p();
            a.push(a_i);
            minus_a.push(-a_i);
        }

        // in the paper, A_1 wraps commitments A_0, A_{l+1} in G1
        let A_0 = self.p_1 * a[0];
        let A_lt1 = Z_0 * a[0] + G1Projective::multi_exp(message.as_slice(), &minus_a[1..]); // A_{l+1}

        // in the paper, A_2 wraps commitments \hat A_1, \hat A_2, ..., \hat A_l in G2
        let mut A_2: Vec<G2Projective> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            A_2.push(self.p_2 * a[i + 1]);
        }

        // Use hash fuction instead of receiving the challenge from the verifier
        let c = self.hash_secret_and_statement_pi_r2_p0(
            hasher, &A_0, &A_lt1, &A_2, Z_1, Y_1_0, lpk_0, message,
        );

        // q wraps q_0 q_1, ..., q_{l+1}
        let mut q: Vec<Scalar> = Vec::with_capacity(self.l + 1);
        q.push(a[0] - c * y_prm_0);
        for i in 1..(self.l + 1) {
            q.push(a[i] - c * sk_0[i - 1]);
        }

        (vec![A_0, A_lt1], A_2, c, q)
    }

    /// Hash function uses not only the commitment but also the statement and message as input
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    fn hash_secret_and_statement_pi_r2_p0(
        &self,
        hasher: &Hasher,
        A_0: &G1Projective,
        A_lt1: &G1Projective,
        A_2: &[G2Projective],
        Z_1: &G1Projective,
        Y_1_0: &G1Projective,
        lpk_0: &[G2Projective],
        message: &[G1Projective],
    ) -> Scalar {
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_0).to_compressed());
        h.update(&G1Affine::from(A_lt1).to_compressed());
        for alpha in A_2.iter().take(self.l) {
            h.update(&G2Affine::from(alpha).to_compressed());
        }
        h.update(&G1Affine::from(Z_1).to_compressed());
        h.update(&G1Affine::from(Y_1_0).to_compressed());
        for key in lpk_0.iter().take(self.l) {
            h.update(&G2Affine::from(key).to_compressed());
        }
        for msg in message.iter().take(self.l) {
            h.update(&G1Affine::from(msg).to_compressed());
        }
        digest_into_scalar(h.finalize())
    }

    /// Verifier is Party 1
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zkpok_pi_r2_p0_verifier(
        &self,
        Z_0: &G1Projective,
        Z_1: &G1Projective,
        Y_1_0: &G1Projective,
        message: &Vec<G1Projective>,
        lpk_0: &[G2Projective],
        A_1: &[G1Projective],
        A_2: &Vec<G2Projective>,
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        let mut minus_q = Vec::with_capacity(self.l + 1);
        for q_i in q.iter() {
            minus_q.push(-q_i);
        }
        let mut B_2: Vec<G2Projective> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            B_2.push(self.p_2 * q[i + 1] + lpk_0[i] * c);
        }

        A_1[0].eq(&(self.p_1 * q[0] + Y_1_0 * c))
            && A_1[1].eq(&(Z_0 * q[0]
                + G1Projective::multi_exp(message.as_slice(), &minus_q[1..])
                + Z_1 * c))
            && A_2.eq(&B_2)
    }

    /// 2-party interactive signing algorithm. Round 2 of P1
    /// Unblind the signature and re-randomize it with y_1
    /// The deliverable isn't blinded, and it keeps the same structure of the original mercurial signature scheme
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round2_P1(
        &self,
        Z_0: &G1Projective,
        r: &Scalar,
        Y_1_0: &G1Projective,
        y_1: Scalar,
        Y_1: &G1Projective,
        Y_2: &G2Projective,
        hasher: &Hasher,
    ) -> (DistributedMercurialSignature, bool) {
        let Z = (*Z_0 + self.p_1 * (-r)) * y_1;

        // inv_y is used as y' (y prime) in the ZKPoK protocol represented in the paper
        let inv_y = y_1.invert().unwrap(); // inv_y means 1/y_1

        // Execute the ZKPoK protocol between Party 1 (Prover) and Party 0 (Verifier)
        let (A_1, c, q) = self.zkpok_pi_r2_p1_prover(&Z, Y_1, Z_0, Y_1_0, r, &inv_y, hasher);
        let pi_r2_p1 = self.zkpok_pi_r2_p1_verifier(&Z, Y_1, Z_0, Y_1_0, &A_1, &c, &q);

        let sigma = DistributedMercurialSignature {
            Z,
            Y_1: *Y_1,
            Y_2: *Y_2,
        };
        (sigma, pi_r2_p1)
    }

    /// Prover is Party 1
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zkpok_pi_r2_p1_prover(
        &self,
        Z: &G1Projective,
        Y_1: &G1Projective,
        Z_0: &G1Projective,
        Y_1_0: &G1Projective,
        r: &Scalar,
        y_prm: &Scalar,
        hasher: &Hasher,
    ) -> (Vec<G1Projective>, Scalar, Vec<Scalar>) {
        let a_0 = random_z_star_p();
        let a_1 = random_z_star_p();

        // in the paper, A wraps commitments A_0, A_1 in G1
        let A_0 = Z * a_0 + self.p_1 * a_1;
        let A_1 = Y_1_0 * a_0;

        // Use hash fuction instead of receiving the challenge from the verifier
        let c = self.hash_secret_and_statement_pi_r2_p1(hasher, &A_0, &A_1, Z_0, Y_1, Y_1_0);

        // q wraps q_0 q_1
        let q_0 = a_0 - c * y_prm;
        let q_1 = a_1 - c * r;

        (vec![A_0, A_1], c, vec![q_0, q_1])
    }

    #[allow(non_snake_case, non_camel_case_types)]
    fn hash_secret_and_statement_pi_r2_p1(
        &self,
        hasher: &Hasher,
        A_0: &G1Projective,
        A_1: &G1Projective,
        Z_0: &G1Projective,
        Y_1: &G1Projective,
        Y_1_0: &G1Projective,
    ) -> Scalar {
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_0).to_compressed());
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G1Affine::from(Z_0).to_compressed());
        h.update(&G1Affine::from(Y_1).to_compressed());
        h.update(&G1Affine::from(Y_1_0).to_compressed());
        let value_before_mod = h.finalize();
        digest_into_scalar(value_before_mod)
    }

    /// Verifier is Party 0
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zkpok_pi_r2_p1_verifier(
        &self,
        Z: &G1Projective,
        Y_1: &G1Projective,
        Z_0: &G1Projective,
        Y_1_0: &G1Projective,
        A: &[G1Projective],
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        A[0].eq(&(Z * q[0] + self.p_1 * q[1] + Z_0 * c)) && A[1].eq(&(Y_1_0 * q[0] + Y_1 * c))
    }

    /// Verification algorithm. The message signed is a vector of elements in G1
    pub fn verify(
        &self,
        pk: &[G2Projective],
        message: &[G1Projective],
        sigma: &DistributedMercurialSignature,
    ) -> bool {
        let mut pair_1 = pairing(&G1Affine::from(message[0]), &G2Affine::from(pk[0]));
        for i in 1..self.l {
            pair_1 += pairing(&G1Affine::from(message[i]), &G2Affine::from(pk[i]));
        }
        let pair_2 = pairing(&G1Affine::from(sigma.Z), &G2Affine::from(sigma.Y_2));
        let pair_3 = pairing(&G1Affine::from(sigma.Y_1), &G2Affine::from(self.p_2));
        let pair_4 = pairing(&G1Affine::from(self.p_1), &G2Affine::from(sigma.Y_2));

        pair_1.eq(&pair_2) && pair_3.eq(&pair_4)
    }
}
