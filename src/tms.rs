use blake3::Hash;
use blake3::Hasher;
use blstrs::*;
use crypto_bigint::Encoding;
use crypto_bigint::U256;
use ff::Field;
use group::Group;
use rand::seq::SliceRandom;

#[derive(Debug, Clone, Copy)]
pub struct ThresholdMercurialSignatureScheme {
    _p: U256,          // order of the groups, p
    l: usize,          // lengths of keys and messages
    p_1: G1Projective, // generator of G1
    p_2: G2Projective, // generator of G2
    n: usize,          // number of members
    t: usize,          // threshold of signers
}

#[allow(non_snake_case, non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdMercurialSignature {
    pub Z: G1Projective,
    pub Y_1: G1Projective, // in the paper, Y_1 is represented as Y
    pub Y_2: G2Projective, // in the paper, Y_2 is represented as \hat{Y}
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

impl ThresholdMercurialSignatureScheme {
    pub fn new(el: usize, mem: usize, th: usize) -> ThresholdMercurialSignatureScheme {
        ThresholdMercurialSignatureScheme {
            _p: U256::from_be_hex(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            ),
            l: el,
            p_1: G1Projective::generator(),
            p_2: G2Projective::generator(),
            n: mem,
            t: th,
        }
    }

    // Generate keys for the members
    pub fn key_gen(&self) -> (Vec<Vec<Scalar>>, Vec<Vec<G2Projective>>, Vec<G2Projective>) {
        // sk is the secret vector corresponding to the singing keys of the original mercurial signature scheme
        // sk is not allowed to open to anyone and in the paper represented as sk = (x_1,...,x_l)
        let mut sk: Vec<Scalar> = Vec::with_capacity(self.l);
        // pk is verifcation key
        let mut pk: Vec<G2Projective> = Vec::with_capacity(self.l);
        for _ in 0..self.l {
            let x = random_z_star_p();
            sk.push(x);
            pk.push(self.p_2 * x);
        }

        // lsk wraps the local share for n members
        // lsk = (sk_1,...,sk_n) = ((x_1^1,...,x_1^l),...,(x_n^1,...,x_n^l))
        let mut lsk: Vec<Vec<Scalar>> = Vec::with_capacity(self.n);
        // lpk wraps the local share for n members
        // lpk = (pk_1,...,pk_n) = ((\hat P^{x^1_1},...,\hat P^{x^l_1}),...,(\hat P^{x^1_n},...,\hat P^{x^l_n}))
        let mut lpk: Vec<Vec<G2Projective>> = Vec::with_capacity(self.n);

        // The local share is computed by (t,n)-threshold method proposed by Shamir in 1979
        // The secret is distributed into n shares with t-1 degree polynomial function defined in Zp Scalar field
        let mut w: Vec<Vec<Scalar>> = Vec::with_capacity(self.l);
        for _ in 0..self.l {
            let mut w_i: Vec<Scalar> = Vec::with_capacity(self.t - 1);
            for _ in 0..self.t {
                w_i.push(random_z_star_p());
            }
            w.push(w_i);
        }

        for j in 1..self.n + 1 {
            // in the paper, lsk is represented as sk_j = (x_j^1,...,x_j^l)
            let mut lsk_j: Vec<Scalar> = Vec::with_capacity(self.l);
            // in the paper, lpk is represented as pk_j = (\hat P^{x^1_j},..., \hat P^{x^l_j})
            let mut lpk_j: Vec<G2Projective> = Vec::with_capacity(self.l);
            let id: Scalar = Scalar::from(j as u64);
            for i in 0..self.l {
                let mut f: Scalar = sk[i];
                for d in 1..self.t {
                    let dim: u64 = d as u64;
                    f += w[i][d - 1] * id.pow([dim]);
                }
                lsk_j.push(f);
                lpk_j.push(self.p_2 * f);
            }
            lsk.push(lsk_j);
            lpk.push(lpk_j);
        }

        (lsk, lpk, pk)
    }

    /// Generate a vector of l elements in G1, chosen randomly
    /// Doesn't correspond to a part of the scheme but it is useful to test the TSign algorithm
    pub fn random_message(&self) -> Vec<G1Projective> {
        let mut message: Vec<G1Projective> = Vec::with_capacity(self.l);
        for _ in 0..self.l {
            message.push(self.p_1 * random_z_star_p());
        }
        message
    }

    /// In advance, random value's share is generated and stored in matrix
    /// In stead of Pederson's VSS protocol, random sampling and additive sharing are used for preparation for the online part.
    /// To focus on the evaluation of the online part, the commitment W_j = G^{w_j} H^{s_j} is also computed in advance.
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn rnd_share_gen(
        &self,
    ) -> (
        Vec<Scalar>,       // r_j (1 \leq j \leq t)
        Vec<Scalar>,       // w_j (1 \leq j \leq t)
        G1Projective,      // H \in G1
        Vec<Scalar>,       // s_j (1 \leq j \leq t)
        Vec<G1Projective>, // W_j (1 \leq j \leq t) \in G1
    ) {
        let mut rs: Vec<Scalar> = Vec::with_capacity(self.t);
        let mut ws: Vec<Scalar> = Vec::with_capacity(self.t);
        let mut ss: Vec<Scalar> = Vec::with_capacity(self.t);
        let mut cap_ws: Vec<G1Projective> = Vec::with_capacity(self.t);

        let mut r_frags_list: Vec<Vec<Scalar>> = Vec::with_capacity(self.t);
        for _ in 0..self.t {
            let mut r_j_frags_list: Vec<Scalar> = Vec::with_capacity(self.t);
            let mut r_j = Scalar::ZERO;
            for _ in 0..self.t {
                let r_j_to_i = random_z_star_p();
                r_j += r_j_to_i;
                r_j_frags_list.push(r_j_to_i);
            }
            rs.push(r_j); // r_j = \sum r_{ji}
            r_frags_list.push(r_j_frags_list);
        }

        let pH = self.p_1 * random_z_star_p();

        for j in 0..self.t {
            let mut sum_r_ij = Scalar::ZERO;
            for i in 0..self.t {
                sum_r_ij += r_frags_list[i][j]
            }
            let w_j = rs[j] - sum_r_ij; // w_j = r_j - \sum r_{ij}
            ws.push(w_j);
            let s_j = random_z_star_p();
            ss.push(s_j);
            cap_ws.push(self.p_1 * w_j + pH * s_j);
        }

        (rs, ws, pH, ss, cap_ws)
    }

    /// Multi-party interactive signing algorithm
    /// The message signed is a vector of elements in G1
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        message: &Vec<G1Projective>,
        lsk: &[Vec<Scalar>],
        lpk: &[Vec<G2Projective>],
        r: &[Scalar],
        w: &[Scalar],
        ph: &G1Projective,
        s: &[Scalar],
        W: &[G1Projective],
    ) -> ThresholdMercurialSignature {
        // If ZKPoK is failed, the algorithm returns failed_res and the signing process is stopped
        let failed_res = ThresholdMercurialSignature {
            Z: G1Projective::identity(),
            Y_1: G1Projective::identity(),
            Y_2: G2Projective::identity(),
        };

        // Shuffle and select t members from n members as signers
        // member_ids is the list of "members' id"
        let mut member_ids: Vec<usize> = Vec::with_capacity(self.n);
        for i in 1..self.n + 1 {
            member_ids.push(i);
        }
        let mut rng = rand::thread_rng();
        member_ids.shuffle(&mut rng);
        // signer_ids is the list of "signers' id" selected from members
        let mut signer_ids: Vec<Scalar> = Vec::with_capacity(self.t);
        for id in member_ids.iter().take(self.t) {
            signer_ids.push(Scalar::from(*id as u64));
        }

        // Hash function is generated here
        // Each party uses the same hash function by cloning
        let hasher = blake3::Hasher::new();

        // "inter ps stor" means "intermediate parties' storage"
        // For the intermediate parties, ip vector plays a role of temporary storage of values
        // For example, Y_1_inter_ps_stor[j] and Y_2_inter_ps_stor[j] are used to store Y_1_uj and Y_2_uj
        let mut Y_1_inter_ps_stor: Vec<G1Projective> = Vec::with_capacity(self.t - 1);
        let mut Y_2_inter_ps_stor: Vec<G2Projective> = Vec::with_capacity(self.t - 1);
        // Round 1 of the first party P_{u_1}
        let (
            Y_1_u1,    // is represented as Y_{u_1} in the paper
            Y_2_u1,    // is represented as \hat Y_{u_1} in the paper
            pi_r1_pu1, // is represented as \pi^{(1)}_{u_1} in the paper
            y_u1, // party u_1 doesn't pass y_u1 (just for holding in party u_1 to use in the next round)
        ) = self.sign_round1_Pu1(&hasher);
        if !pi_r1_pu1 {
            println!("==== Round 1 of First Party is failed ====");
            return failed_res;
        }
        Y_1_inter_ps_stor.push(Y_1_u1);
        Y_2_inter_ps_stor.push(Y_2_u1);

        // y_inter_ps_stor, lambda_inter_ps_stor, H_inter_ps_stor are used to store temporary values of y_{u_j}, lambda_j, H_{u_j} in the paper, respectively
        let mut y_inter_ps_stor: Vec<Scalar> = Vec::with_capacity(self.t - 2);
        let mut lambda_inter_ps_stor: Vec<Scalar> = Vec::with_capacity(self.t - 2);
        let mut H_inter_ps_stor: Vec<G1Projective> = Vec::with_capacity(self.t - 2);
        for j in 1..self.t - 1 {
            // Round 1 of the intermediate party P_{u_j}
            let (
                Y_1_uj,    // is represented as Y_{u_j} in the paper
                Y_2_uj,    // is represented as \hat Y_{u_j} in the paper
                pi_r1_puj, // is represented as \pi^{(1)}_{u_j} in the paper
                y_uj, // party u_j doesn't pass y_uj (just for holding in party u_j to use in the next round)
                lambda_j, // is Lagrange Coefficient in the paper
                H_uj, // party u_j doesn't pass H_uj (just for holding in party u_j to use in the next round)
            ) = self.sign_round1_Puj(
                &hasher,
                &signer_ids, // is represented as (u_1,...,u_t) in the paper (used for Lagrange Coefficients)
                j,
                &Y_1_inter_ps_stor[j - 1],
                &Y_2_inter_ps_stor[j - 1],
                message,
                &lsk[member_ids[j] - 1],
                &r[j],
            );
            if !pi_r1_puj {
                println!("==== Round 1 of Middle Party is failed ====");
                return failed_res;
            }
            Y_1_inter_ps_stor.push(Y_1_uj);
            Y_2_inter_ps_stor.push(Y_2_uj);
            y_inter_ps_stor.push(y_uj);
            lambda_inter_ps_stor.push(lambda_j);
            H_inter_ps_stor.push(H_uj);
        }

        // Round 2 of the last party P_{u_t}
        let (
            Y_1,       // used in final signature (is represented as Y in the paper)
            Y_2,       // used in final signature (is represented as \hat Y in the paper)
            pi_r2_put, // is represented as \pi^{(2)}_{u_t} in the paper
            y_ut, // party u_t doesn't pass y_ut (just for holding in party u_t to use in the next round)
            I_ut, // is represented as I_{u_t} in the paper
        ) = self.sign_round2_Put(
            &hasher,
            &signer_ids, // is represented as (u_1,...,u_t) in the paper (global information for all parties)
            &Y_1_inter_ps_stor[Y_1_inter_ps_stor.len() - 1],
            &Y_2_inter_ps_stor[Y_2_inter_ps_stor.len() - 1],
            message,
            &lsk[member_ids[self.t - 1] - 1],
            &r[self.t - 1],
            &w[self.t - 1],
            ph, // H \in G1
            &s[self.t - 1],
            &W[self.t - 1],
            &lpk[member_ids[self.t - 1] - 1],
        );
        if !pi_r2_put {
            println!("==== Round 2 of Last Party is failed ====");
            return failed_res;
        }

        // In round 2, each of parties update I by adding H_{u_j} to I_{u_{j+1}}
        let mut I = I_ut;
        for j in (1..self.t - 1).rev() {
            // Round 2 of the intermediate party P_{u_j}
            let (
                I_uj,      // is represented as I_{u_j} in the paper
                pi_r2_puj, // is represented as \pi^{(2)}_{u_j} in the paper
            ) = self.sign_round2_Puj(
                &hasher,
                &I,
                &H_inter_ps_stor[j - 1],
                &Y_1_inter_ps_stor[j - 1], // received from u_{j-1} in round 1
                &r[j],                     // is generated in round 1
                message,
                &lambda_inter_ps_stor[j - 1], // is calculated in round 1
                &lsk[member_ids[j] - 1],
                &w[j],
                ph, // H \in G1
                &s[j],
                &W[j],
                &lpk[member_ids[j] - 1],
            );
            if !pi_r2_puj {
                println!("==== Round 2 of Middle Party is failed ====");
                return failed_res;
            }
            I = I_uj;
        }

        // Round 3 of the first party P_{u_1}
        let (
            Z_u1,      // is represented as Z_{u_1} in the paper
            pi_r3_pu1, // is represented as \pi^{(3)}_{u_1} in the paper
        ) = self.sign_round3_Pu1(
            &hasher,
            &signer_ids, // is represented as (u_1,...,u_t) in the paper (global information for all parties)
            &I,
            message,
            &lsk[member_ids[0] - 1],
            &w[0],
            ph,
            &s[0],
            &W[0],
            &y_u1,   // is generated in round 1
            &Y_1_u1, // is calculated in round 1
            &lpk[member_ids[0] - 1],
        );
        if !pi_r3_pu1 {
            println!("==== Round 3 of First Party is failed ====");
            return failed_res;
        }

        let mut Z = Z_u1;
        for j in 1..self.t - 1 {
            // Round 3 of the intermediate party P_{u_j}
            let (
                Z_uj,      // is represented as Z_{u_j} in the paper
                pi_r3_puj, // is represented as \pi^{(3)}_{u_j} in the paper
            ) = self.sign_round3_Puj(
                &hasher,
                &Z,
                &r[j],                     // is generated in round 1
                &y_inter_ps_stor[j - 1],   // is generated in round 1
                &Y_1_inter_ps_stor[j],     // is calculated in round 1
                &Y_1_inter_ps_stor[j - 1], // received from u_{j-1} in round 1
            );
            if !pi_r3_puj {
                println!("==== Round 3 of Middle Party is failed ====");
                return failed_res;
            }
            Z = Z_uj;
        }

        // Round 3 of the last party P_{u_t}
        let (
            sigma,
            pi_r3_put, // is represented as \pi^{(3)}_{u_t} in the paper
        ) = self.sign_round3_Put(
            &hasher,
            &Z,
            &r[self.t - 1],                                  // is generated in round 2
            &y_ut,                                           // is generated in round 2
            &Y_1,                                            // is calculated in round 2
            &Y_2,                                            // is calculated in round 2
            &Y_1_inter_ps_stor[Y_1_inter_ps_stor.len() - 1], // received from u_{t-1} in round 2
        );
        if !pi_r3_put {
            println!("==== Round 3 of Last Party is failed ====");
            return failed_res;
        }

        sigma
    }

    /// t-party interactive signing algorithm. Round 1 of the first party P_{u_1}
    /// Commit random y_{u_1}
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign_round1_Pu1(&self, hasher: &Hasher) -> (G1Projective, G2Projective, bool, Scalar) {
        let y_u1 = random_z_star_p();
        let inv_y_u1 = y_u1.invert().unwrap();
        let Y_1_u1 = self.p_1 * inv_y_u1;
        let Y_2_u1 = self.p_2 * inv_y_u1;

        // Execute the ZKPoK protocol
        let (A_1, A_2, c, q) = self.zk_u1_1_prover(hasher, &Y_1_u1, &Y_2_u1, &y_u1);
        let pi_r1_pu1 = self.zk_u1_1_verifier(&Y_1_u1, &Y_2_u1, &A_1, &A_2, &c, &q);

        (Y_1_u1, Y_2_u1, pi_r1_pu1, y_u1)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn zk_u1_1_prover(
        &self,
        hasher: &Hasher,
        Y_1_u1: &G1Projective,
        Y_2_u1: &G2Projective,
        y_u1: &Scalar,
    ) -> (G1Projective, G2Projective, Scalar, Scalar) {
        let a = random_z_p();
        let A_1 = Y_1_u1 * a; // is commitments in G1
        let A_2 = Y_2_u1 * a; // is commitments in G2

        // Challenge c is computed by hash instead of response by verifier using not only commitment but also statements
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G2Affine::from(A_2).to_compressed());
        h.update(&G1Affine::from(Y_1_u1).to_compressed());
        h.update(&G2Affine::from(Y_2_u1).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q = a - c * y_u1;

        (A_1, A_2, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn zk_u1_1_verifier(
        &self,
        Y_1_u1: &G1Projective,
        Y_2_u1: &G2Projective,
        A_1: &G1Projective,
        A_2: &G2Projective,
        c: &Scalar,
        q: &Scalar,
    ) -> bool {
        A_1.eq(&(Y_1_u1 * q + self.p_1 * c)) && A_2.eq(&(Y_2_u1 * q + self.p_2 * c))
    }

    /// t-party interactive signing algorithm. Round 1 of the middle party P_{u_j}
    /// Commit random y_{u_j} and compute H_{u_j} which is the blinded factor of Z
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round1_Puj(
        &self,
        hasher: &Hasher,
        signer_ids: &[Scalar],
        id: usize,
        Y_1_u1: &G1Projective,
        Y_2_u1: &G2Projective,
        M: &Vec<G1Projective>,
        s: &[Scalar],
        r_uj: &Scalar,
    ) -> (
        G1Projective,
        G2Projective,
        bool,
        Scalar,
        Scalar,
        G1Projective,
    ) {
        let y_uj = random_z_star_p();
        let inv_y_uj = y_uj.invert().unwrap();
        let Y_1_uj = Y_1_u1 * inv_y_uj;
        let Y_2_uj = Y_2_u1 * inv_y_uj;

        // lambda_j is the product of the Lagrange Coefficients
        let mut lambda_j = signer_ids[0] * (signer_ids[0] - signer_ids[id]).invert().unwrap();
        for m in 1..self.t {
            if m == id {
                continue;
            }
            lambda_j *= signer_ids[m] * (signer_ids[m] - signer_ids[id]).invert().unwrap();
        }

        let mut H_uj = Y_1_u1 * r_uj;
        let mut lambda_dot_s: Vec<Scalar> = Vec::with_capacity(self.l);
        for key in s.iter().take(self.l) {
            lambda_dot_s.push(lambda_j * key);
        }
        H_uj += G1Projective::multi_exp(M.as_slice(), &lambda_dot_s);

        // Execute the ZKPoK protocol
        let (A_1, A_2, c, q) = self.zk_uj_1_prover(hasher, &Y_1_uj, &Y_2_uj, &y_uj);
        let pi_r1_puj = self.zk_uj_1_verifier(&Y_1_uj, &Y_2_uj, Y_1_u1, Y_2_u1, &A_1, &A_2, &c, &q);

        (Y_1_uj, Y_2_uj, pi_r1_puj, y_uj, lambda_j, H_uj)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    pub fn zk_uj_1_prover(
        &self,
        hasher: &Hasher,
        Y_1_uj: &G1Projective,
        Y_2_uj: &G2Projective,
        y_uj: &Scalar,
    ) -> (G1Projective, G2Projective, Scalar, Scalar) {
        let a = random_z_p();
        let A_1 = Y_1_uj * a; // is commitments in G1
        let A_2 = Y_2_uj * a; // is commitments in G2

        // Challenge c is computed by hash instead of response by verifier using not only commitment but also statements
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        h.update(&G2Affine::from(A_2).to_compressed());
        h.update(&G1Affine::from(Y_1_uj).to_compressed());
        h.update(&G2Affine::from(Y_2_uj).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q = a - c * y_uj;

        (A_1, A_2, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_uj_1_verifier(
        &self,
        Y_1_uj: &G1Projective,
        Y_2_uj: &G2Projective,
        Y_1_u1: &G1Projective,
        Y_2_u1: &G2Projective,
        A_1: &G1Projective,
        A_2: &G2Projective,
        c: &Scalar,
        q: &Scalar,
    ) -> bool {
        A_1.eq(&(Y_1_uj * q + Y_1_u1 * c)) && A_2.eq(&(Y_2_uj * q + Y_2_u1 * c))
    }

    /// t-party interactive signing algorithm. Round 2 of the last party P_{u_t}
    /// Commit random y_{u_t} and compute I_{u_t} which is the blinded factor of Z
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round2_Put(
        &self,
        hasher: &Hasher,
        signer_ids: &[Scalar],
        Y_1_uj: &G1Projective,
        Y_2_uj: &G2Projective,
        M: &Vec<G1Projective>,
        x: &[Scalar], // secret share of P_{u_t}
        r_ut: &Scalar,
        w_ut: &Scalar,
        ph: &G1Projective,
        s_ut: &Scalar,
        W_ut: &G1Projective,
        lpk: &[G2Projective],
    ) -> (G1Projective, G2Projective, bool, Scalar, G1Projective) {
        let y_ut = random_z_star_p();
        let inv_y_ut = y_ut.invert().unwrap();
        let Y_1 = Y_1_uj * inv_y_ut;
        let Y_2 = Y_2_uj * inv_y_ut;

        let mut lambda_k =
            signer_ids[0] * (signer_ids[0] - signer_ids[self.t - 1]).invert().unwrap();
        for m in 1..self.t - 1 {
            lambda_k *= signer_ids[m] * (signer_ids[m] - signer_ids[self.t - 1]).invert().unwrap();
        }

        let mut I_ut = Y_1_uj * r_ut;
        let mut lambda_dot_s: Vec<Scalar> = Vec::with_capacity(self.l);
        for key in x.iter().take(self.l) {
            lambda_dot_s.push(lambda_k * key);
        }
        I_ut += G1Projective::multi_exp(M.as_slice(), &lambda_dot_s);
        I_ut += self.p_1 * w_ut;

        // Execute the ZKPoK protocol
        let (A_1, A_12, A_2, c, q) = self.zk_ut_2_prover(
            hasher, Y_1_uj, r_ut, M, &lambda_k, x, w_ut, ph, s_ut, W_ut, &I_ut, lpk,
        );
        let pi_r2_put = self.zk_ut_2_verifier(
            &I_ut, Y_1_uj, M, &lambda_k, ph, W_ut, lpk, &A_1, &A_12, &A_2, &c, &q,
        );

        (Y_1, Y_2, pi_r2_put, y_ut, I_ut)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_ut_2_prover(
        &self,
        hasher: &Hasher,
        Y_1_uj: &G1Projective,
        r_ut: &Scalar,
        M: &Vec<G1Projective>,
        lambda_k: &Scalar,
        x: &[Scalar],
        w_ut: &Scalar,
        ph: &G1Projective,
        s_ut: &Scalar,
        W_ut: &G1Projective,
        I_ut: &G1Projective,
        lpk: &[G2Projective],
    ) -> (
        G1Projective,
        G1Projective,
        Vec<G2Projective>,
        Scalar,
        Vec<Scalar>,
    ) {
        let mut a: Vec<Scalar> = Vec::with_capacity(self.l + 3);
        for _ in 0..self.l + 3 {
            a.push(random_z_p());
        }

        let mut A_1 = Y_1_uj * a[0]; // is commitments in G1
        let mut lambda_dot_a: Vec<Scalar> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            lambda_dot_a.push(lambda_k * a[i + 1]);
        }
        A_1 += G1Projective::multi_exp(M.as_slice(), &lambda_dot_a);
        A_1 += self.p_1 * a[self.l + 1];
        let A_12 = self.p_1 * a[self.l + 1] + ph * a[self.l + 2];

        let mut A_2: Vec<G2Projective> = Vec::with_capacity(self.l); // is commitments in G2
        for i in 0..self.l {
            A_2.push(self.p_2 * a[i + 1]);
        }

        // Challenge c is computed by hash instead of response by verifier using not only commitment but also statements
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        for alpha in A_2.iter().take(self.l) {
            h.update(&G2Affine::from(alpha).to_compressed());
        }
        h.update(&G1Affine::from(I_ut).to_compressed());
        h.update(&G1Affine::from(W_ut).to_compressed());
        for key in lpk.iter().take(self.l) {
            h.update(&G2Affine::from(key).to_compressed());
        }
        for msg in M.iter().take(self.l) {
            h.update(&G1Affine::from(msg).to_compressed());
        }
        let c = digest_into_scalar(h.finalize());

        let mut q: Vec<Scalar> = Vec::with_capacity(self.l + 3);
        q.push(a[0] - c * r_ut);
        for i in 0..self.l {
            q.push(a[i + 1] - c * x[i]);
        }
        q.push(a[self.l + 1] - c * w_ut);
        q.push(a[self.l + 2] - c * s_ut);

        (A_1, A_12, A_2, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_ut_2_verifier(
        &self,
        I_ut: &G1Projective,
        Y_1_uj: &G1Projective,
        M: &Vec<G1Projective>,
        lambda_k: &Scalar,
        ph: &G1Projective,
        W_ut: &G1Projective,
        lpk: &[G2Projective],
        A_1: &G1Projective,
        A_12: &G1Projective,
        A_2: &Vec<G2Projective>,
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        let mut lambda_dot_q: Vec<Scalar> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            lambda_dot_q.push(lambda_k * q[i + 1]);
        }
        let B_1 = Y_1_uj * q[0]
            + G1Projective::multi_exp(M.as_slice(), &lambda_dot_q)
            + self.p_1 * q[self.l + 1]
            + I_ut * c;

        let B_12 = self.p_1 * q[self.l + 1] + ph * q[self.l + 2] + W_ut * c;

        let mut B_2: Vec<G2Projective> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            B_2.push(self.p_2 * q[i + 1] + lpk[i] * c);
        }

        A_1.eq(&B_1) && A_12.eq(&B_12) && A_2.eq(&B_2)
    }

    /// t-party interactive signing algorithm. Round 2 of the middle party P_{u_j}
    /// Compute the product of blinded factors as partial signatures
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round2_Puj(
        &self,
        hasher: &Hasher,
        I_ut: &G1Projective,
        H_uj: &G1Projective,
        Y_1_u1: &G1Projective,
        r_uj: &Scalar,
        M: &[G1Projective],
        lambda_j: &Scalar,
        x: &[Scalar],
        w_uj: &Scalar,
        ph: &G1Projective,
        s_uj: &Scalar,
        W_uj: &G1Projective,
        lpk: &[G2Projective],
    ) -> (G1Projective, bool) {
        let I_uj = I_ut + H_uj + self.p_1 * w_uj;

        // Execute the ZKPoK protocol
        let (A_1, A_12, A_2, c, q) = self.zk_uj_2_prover(
            hasher, &I_uj, I_ut, Y_1_u1, r_uj, M, lambda_j, x, w_uj, ph, s_uj, W_uj, lpk,
        );
        let pi_r2_puj = self.zk_uj_2_verifier(
            &I_uj, I_ut, Y_1_u1, M, lambda_j, ph, W_uj, lpk, &A_1, &A_12, &A_2, &c, &q,
        );

        (I_uj, pi_r2_puj)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_uj_2_prover(
        &self,
        hasher: &Hasher,
        I_uj: &G1Projective,
        I_ut: &G1Projective,
        Y_1_u1: &G1Projective,
        r_uj: &Scalar,
        M: &[G1Projective],
        lambda_j: &Scalar,
        x: &[Scalar],
        w_uj: &Scalar,
        ph: &G1Projective,
        s_uj: &Scalar,
        W_uj: &G1Projective,
        lpk: &[G2Projective],
    ) -> (
        G1Projective,
        G1Projective,
        Vec<G2Projective>,
        Scalar,
        Vec<Scalar>,
    ) {
        let mut a: Vec<Scalar> = Vec::with_capacity(self.l + 3);
        for _ in 0..self.l + 3 {
            a.push(random_z_p());
        }

        let mut lambda_dot_a: Vec<Scalar> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            lambda_dot_a.push(lambda_j * a[i + 1]);
        }
        let A_1 = I_ut
            + Y_1_u1 * a[0]
            + G1Projective::multi_exp(M, &lambda_dot_a)
            + self.p_1 * a[self.l + 1]; // is commitments in G1

        let A_12 = self.p_1 * a[self.l + 1] + ph * a[self.l + 2];

        let mut A_2: Vec<G2Projective> = Vec::with_capacity(self.l); // is commitments in G2
        for i in 0..self.l {
            A_2.push(self.p_2 * a[i + 1]);
        }

        // Challenge c is computed by hash instead of response by verifier using not only commitment but also statements
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_1).to_compressed());
        for alpha in A_2.iter().take(self.l) {
            h.update(&G2Affine::from(alpha).to_compressed());
        }
        h.update(&G1Affine::from(I_uj).to_compressed());
        h.update(&G1Affine::from(W_uj).to_compressed());
        for key in lpk.iter().take(self.l) {
            h.update(&G2Affine::from(key).to_compressed());
        }
        for msg in M.iter().take(self.l) {
            h.update(&G1Affine::from(msg).to_compressed());
        }
        let c = digest_into_scalar(h.finalize());

        let mut q: Vec<Scalar> = Vec::with_capacity(self.l + 3);
        q.push(a[0] - c * r_uj);
        for i in 0..self.l {
            q.push(a[i + 1] - c * x[i]);
        }
        q.push(a[self.l + 1] - c * w_uj);
        q.push(a[self.l + 2] - c * s_uj);

        (A_1, A_12, A_2, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_uj_2_verifier(
        &self,
        I_uj: &G1Projective,
        I_ut: &G1Projective,
        Y_1_u1: &G1Projective,
        M: &[G1Projective],
        lambda_j: &Scalar,
        ph: &G1Projective,
        W_uj: &G1Projective,
        lpk: &[G2Projective],
        A_1: &G1Projective,
        A_12: &G1Projective,
        A_2: &Vec<G2Projective>,
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        let mut lambda_dot_q: Vec<Scalar> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            lambda_dot_q.push(lambda_j * q[i + 1]);
        }

        let B_1 = I_ut
            + Y_1_u1 * q[0]
            + G1Projective::multi_exp(M, &lambda_dot_q)
            + self.p_1 * q[self.l + 1]
            + I_uj * c
            + I_ut * (-c);

        let B_12 = self.p_1 * q[self.l + 1] + ph * q[self.l + 2] + W_uj * c;

        let mut B_2: Vec<G2Projective> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            B_2.push(self.p_2 * q[i + 1] + lpk[i] * c);
        }

        A_1.eq(&B_1) && A_12.eq(&B_12) && A_2.eq(&B_2)
    }

    /// t-party interactive signing algorithm. Round 3 of the last party P_{u_1}
    /// Compute the product of partial signature and re-randomize it with commited value y_{u_1}
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round3_Pu1(
        &self,
        hasher: &Hasher,
        signer_ids: &[Scalar],
        I_uj: &G1Projective,
        M: &Vec<G1Projective>,
        x: &[Scalar], // secret share of P_{u_1}
        w_u1: &Scalar,
        ph: &G1Projective,
        s_u1: &Scalar,
        W_u1: &G1Projective,
        y_u1: &Scalar,
        Y_1_u1: &G1Projective,
        lpk: &[G2Projective],
    ) -> (G1Projective, bool) {
        let mut lambda_1 =
            signer_ids[self.t - 1] * (signer_ids[self.t - 1] - signer_ids[0]).invert().unwrap();
        for m in 1..self.t - 1 {
            lambda_1 *= signer_ids[m] * (signer_ids[m] - signer_ids[0]).invert().unwrap();
        }
        let mut lambda_dot_s: Vec<Scalar> = Vec::with_capacity(self.l);
        for key in x.iter().take(self.l) {
            lambda_dot_s.push(lambda_1 * key);
        }

        let mut Z_u1 =
            *I_uj + G1Projective::multi_exp(M.as_slice(), &lambda_dot_s) + self.p_1 * w_u1;
        Z_u1 *= y_u1;

        // Execute the ZKPoK protocol
        let y_prm_u1 = y_u1.invert().unwrap(); // is represented as y'_{u_1} in the paper
        let (A_1, A_2, c, q) = self.zk_u1_3_prover(
            hasher, I_uj, Y_1_u1, M, &lambda_1, x, w_u1, ph, s_u1, W_u1, &Z_u1, &y_prm_u1, lpk,
        );
        let pi_r3_pu1 = self.zk_u1_3_verifier(
            I_uj, Y_1_u1, M, &lambda_1, ph, W_u1, &Z_u1, lpk, &A_1, &A_2, &c, &q,
        );

        (Z_u1, pi_r3_pu1)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_u1_3_prover(
        &self,
        hasher: &Hasher,
        I_uj: &G1Projective,
        Y_1_u1: &G1Projective,
        M: &[G1Projective],
        lambda_1: &Scalar,
        x: &[Scalar],
        w_u1: &Scalar,
        ph: &G1Projective,
        s_u1: &Scalar,
        W_u1: &G1Projective,
        Z_u1: &G1Projective,
        y_prm_u1: &Scalar, // in the paper, it is represented as y'_{u_1} = \frac{1}{y_{u_1}}
        lpk: &[G2Projective],
    ) -> (Vec<G1Projective>, Vec<G2Projective>, Scalar, Vec<Scalar>) {
        let mut a: Vec<Scalar> = Vec::with_capacity(self.l + 3);
        let mut minus_a: Vec<Scalar> = Vec::with_capacity(self.l + 3);
        for _ in 0..self.l + 3 {
            let random_a = random_z_p();
            a.push(random_a);
            minus_a.push(-random_a);
        }

        let A_10 = self.p_1 * a[0]; // is commitments in G1

        let mut minus_lambda_dot_a: Vec<Scalar> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            minus_lambda_dot_a.push(lambda_1 * minus_a[i + 1]);
        }
        let A_11 = Z_u1 * a[0]
            + G1Projective::multi_exp(M, &minus_lambda_dot_a)
            + self.p_1 * minus_a[self.l + 1]; // is commitments in G1

        let A_12 = self.p_1 * a[self.l + 1] + ph * a[self.l + 2];

        let mut A_2: Vec<G2Projective> = Vec::with_capacity(self.l); // is commitments in G2
        for i in 0..self.l {
            A_2.push(self.p_2 * a[i + 1]);
        }

        // Challenge c is computed by hash instead of response by verifier using not only commitment but also statements
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A_10).to_compressed());
        h.update(&G1Affine::from(A_11).to_compressed());
        h.update(&G1Affine::from(A_12).to_compressed());

        for alpha in A_2.iter().take(self.l) {
            h.update(&G2Affine::from(alpha).to_compressed());
        }
        h.update(&G1Affine::from(I_uj).to_compressed());
        h.update(&G1Affine::from(Y_1_u1).to_compressed());
        h.update(&G1Affine::from(W_u1).to_compressed());
        for key in lpk.iter().take(self.l) {
            h.update(&G2Affine::from(key).to_compressed());
        }
        for msg in M.iter().take(self.l) {
            h.update(&G1Affine::from(msg).to_compressed());
        }
        let c = digest_into_scalar(h.finalize());

        let mut q: Vec<Scalar> = Vec::with_capacity(self.l + 3);
        q.push(a[0] - c * y_prm_u1);
        for i in 0..self.l {
            q.push(a[i + 1] - c * x[i]);
        }
        q.push(a[self.l + 1] - c * w_u1);
        q.push(a[self.l + 2] - c * s_u1);

        (vec![A_10, A_11, A_12], A_2, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_u1_3_verifier(
        &self,
        I_uj: &G1Projective,
        Y_1_u1: &G1Projective,
        M: &[G1Projective],
        lambda_1: &Scalar,
        ph: &G1Projective,
        W_u1: &G1Projective,
        Z_u1: &G1Projective,
        lpk: &[G2Projective],
        A_1: &[G1Projective],
        A_2: &Vec<G2Projective>,
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        let B_10 = self.p_1 * q[0] + Y_1_u1 * c;
        let mut minus_lambda_dot_q: Vec<Scalar> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            minus_lambda_dot_q.push(-(lambda_1 * q[i + 1]));
        }
        let B_11 = (Z_u1 * q[0]
            + G1Projective::multi_exp(M, &minus_lambda_dot_q)
            + self.p_1 * (-q[self.l + 1]))
            + I_uj * c;

        let B_12 = self.p_1 * q[self.l + 1] + ph * q[self.l + 2] + W_u1 * c;

        let mut B_2: Vec<G2Projective> = Vec::with_capacity(self.l);
        for i in 0..self.l {
            B_2.push(self.p_2 * q[i + 1] + lpk[i] * c);
        }

        A_1[0].eq(&B_10) && A_1[1].eq(&B_11) && A_1[2].eq(&B_12) && A_2.eq(&B_2)
    }

    /// t-party interactive signing algorithm. Round 3 of the middle party P_{u_j}
    /// Unblinding the signature and re-randomize it with commited value y_{u_j}
    #[allow(non_snake_case, non_camel_case_types)]
    pub fn sign_round3_Puj(
        &self,
        hasher: &Hasher,
        Z_u1: &G1Projective,
        r_uj: &Scalar,
        y_uj: &Scalar,
        Y_1_uj: &G1Projective,
        Y_1_u1: &G1Projective,
    ) -> (G1Projective, bool) {
        let mut Z_uj = *Z_u1;
        Z_uj += self.p_1 * (-r_uj);
        Z_uj *= y_uj;

        // Execute the ZKPoK protocol
        let (A, c, q) = self.zk_uj_3_prover(
            hasher,
            &Z_uj,
            Z_u1,
            r_uj,
            &y_uj.invert().unwrap(),
            Y_1_uj,
            Y_1_u1,
        );
        let pi_r3_puj = self.zk_uj_3_verifier(&Z_uj, Z_u1, Y_1_uj, Y_1_u1, &A, &c, &q);

        (Z_uj, pi_r3_puj)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_uj_3_prover(
        &self,
        hasher: &Hasher,
        Z_uj: &G1Projective,
        Z_u1: &G1Projective,
        r_uj: &Scalar,
        y_uj: &Scalar,
        Y_1_uj: &G1Projective,
        Y_1_u1: &G1Projective,
    ) -> (Vec<G1Projective>, Scalar, Vec<Scalar>) {
        let a_0 = random_z_p();
        let a_1 = random_z_p();

        let A = vec![Z_uj * a_0 + self.p_1 * a_1, Y_1_u1 * a_0]; // is commitments in G1

        // Challenge c is computed by hash instead of response by verifier using not only commitment but also statements
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A[0]).to_compressed());
        h.update(&G1Affine::from(A[1]).to_compressed());
        h.update(&G1Affine::from(Z_u1).to_compressed());
        h.update(&G1Affine::from(Y_1_uj).to_compressed());
        h.update(&G1Affine::from(Y_1_u1).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q = vec![a_0 - c * y_uj, a_1 - c * r_uj];

        (A, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_uj_3_verifier(
        &self,
        Z_uj: &G1Projective,
        Z_u1: &G1Projective,
        Y_1_uj: &G1Projective,
        Y_1_u1: &G1Projective,
        A: &[G1Projective],
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        A[0].eq(&(Z_uj * q[0] + self.p_1 * q[1] + Z_u1 * c))
            && A[1].eq(&(Y_1_u1 * q[0] + Y_1_uj * c))
    }

    /// t-party interactive signing algorithm. Round 3 of the last party P_{u_t}
    /// Unblinding the signature and re-randomize it with commited value y_{u_t}
    /// The deliverable is non-blinded signature and it keeps the structure of the original mercurial signature
    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_round3_Put(
        &self,
        hasher: &Hasher,
        Z_uj: &G1Projective,
        r_ut: &Scalar,
        y_ut: &Scalar,
        Y_1: &G1Projective,
        Y_2: &G2Projective,
        Y_1_uj: &G1Projective,
    ) -> (ThresholdMercurialSignature, bool) {
        let mut Z = *Z_uj;
        Z += self.p_1 * (-r_ut);
        Z *= y_ut;

        // Execute the ZKPoK protocol
        let (A, c, q) =
            self.zk_ut_3_prover(hasher, &Z, Z_uj, r_ut, &y_ut.invert().unwrap(), Y_1, Y_1_uj);
        let pi_r3_put = self.zk_ut_3_verifier(&Z, Z_uj, Y_1, Y_1_uj, &A, &c, &q);

        let sigma = ThresholdMercurialSignature {
            Z,
            Y_1: *Y_1,
            Y_2: *Y_2,
        };

        (sigma, pi_r3_put)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_ut_3_prover(
        &self,
        hasher: &Hasher,
        Z: &G1Projective,
        Z_uj: &G1Projective,
        r_ut: &Scalar,
        y_ut: &Scalar,
        Y_1: &G1Projective,
        Y_1_uj: &G1Projective,
    ) -> (Vec<G1Projective>, Scalar, Vec<Scalar>) {
        let a_0 = random_z_p();
        let a_1 = random_z_p();

        let A = vec![Z * a_0 + self.p_1 * a_1, Y_1_uj * a_0]; // is commitments in G1

        // Challenge c is computed by hash instead of response by verifier using not only commitment but also statements
        let mut h = hasher.clone();
        h.update(&G1Affine::from(A[0]).to_compressed());
        h.update(&G1Affine::from(A[1]).to_compressed());
        h.update(&G1Affine::from(Z_uj).to_compressed());
        h.update(&G1Affine::from(Y_1).to_compressed());
        h.update(&G1Affine::from(Y_1_uj).to_compressed());
        let c = digest_into_scalar(h.finalize());

        let q = vec![a_0 - c * y_ut, a_1 - c * r_ut];

        (A, c, q)
    }

    #[allow(non_snake_case, non_camel_case_types)]
    #[allow(clippy::too_many_arguments)]
    pub fn zk_ut_3_verifier(
        &self,
        Z: &G1Projective,
        Z_uj: &G1Projective,
        Y_1: &G1Projective,
        Y_1_uj: &G1Projective,
        A: &[G1Projective],
        c: &Scalar,
        q: &[Scalar],
    ) -> bool {
        A[0].eq(&(Z * q[0] + self.p_1 * q[1] + Z_uj * c)) && A[1].eq(&(Y_1_uj * q[0] + Y_1 * c))
    }

    pub fn verify(
        &self,
        pk: &[G2Projective],
        message: &[G1Projective],
        sigma: &ThresholdMercurialSignature,
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
