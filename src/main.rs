mod dmc;
use dmc::DistributedMercurialSignatureScheme;

mod tms;
use tms::ThresholdMercurialSignatureScheme;

fn exec_dmc() {
    println!("==== Distributed Mercurial Signature Scheme ====");
    let dmc = DistributedMercurialSignatureScheme::new(1);
    let (sk, lpk, pk) = dmc.key_gen();
    // println!("Secret key: {:?}", sk);
    // println!("Local public key: {:?}", lpk);
    // println!("Public key: {:?}", pk);
    let message = dmc.random_message();
    // println!("Message: {:?}", message);
    let sigma = dmc.sign(&sk, &message, &lpk);
    // println!("Signature: {:?}", sigma);
    let result = dmc.verify(&pk, &message, &sigma);
    println!("Verification result: {}", result);
}

fn exec_tms() {
    println!("==== Threshold Mercurial Signature Scheme ====");
    let tms = ThresholdMercurialSignatureScheme::new(5, 10, 5);

    let (sh, lpk, pk) = tms.key_gen();
    // println!("Local share: {:?}", sh);
    // println!("Local public key: {:?}", lpk);
    // println!("Public key: {:?}", pk);

    let message = tms.random_message();

    let (r, w, ph, s, capw) = tms.rnd_share_gen();

    let sigma = tms.sign(&message, &sh, &lpk, &r, &w, &ph, &s, &capw);
    // println!("Signature: {:?}", sigma);

    let result = tms.verify(&pk, &message, &sigma);
    println!("Verification result: {}", result);
}

fn main() {
    exec_dmc();
    exec_tms();
}
