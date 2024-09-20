use dmc::DistributedMercurialSignature;
use dmc::DistributedMercurialSignatureScheme;
use dmc::MercurialSignature;
use dmc::MercurialSignatureScheme;
use tms::ThresholdMercurialSignature;
use tms::ThresholdMercurialSignatureScheme;
use tmslib::{dmc, tms};

use blstrs::*;
use criterion::{criterion_group, criterion_main, Criterion};

/* Bench of mercurial signatures, using blstrs library for computations */

pub fn ms_do_verification(
    message: &Vec<G1Projective>,
    scheme: &MercurialSignatureScheme,
    pk: &Vec<G2Projective>,
    signature: &MercurialSignature,
) -> bool {
    scheme.verify(pk, message, signature)
}

// given all element just computes the signature of a message
pub fn ms_sign_messages(
    message: &Vec<G1Projective>,
    scheme: &MercurialSignatureScheme,
    sk: &Vec<Scalar>,
) {
    let _signature = scheme.sign(sk, message);
}

// pub fn ms_sign_1_attributes(c: &mut Criterion) {
//     let scheme = MercurialSignatureScheme::new(1);
//     let (sk, _pk) = scheme.key_gen();
//     let message = scheme.random_message();
//     c.bench_function("MS signature on 1 elements", |b| {
//         b.iter(|| {
//             ms_sign_messages(&message, &scheme, &sk);
//         })
//     });
// }

pub fn ms_sign_2_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(2);
    let (sk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("MS signature on 2 elements", |b| {
        b.iter(|| {
            ms_sign_messages(&message, &scheme, &sk);
        })
    });
}

pub fn ms_sign_5_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(5);
    let (sk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("MS signature on 5 elements", |b| {
        b.iter(|| {
            ms_sign_messages(&message, &scheme, &sk);
        })
    });
}

pub fn ms_sign_10_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(10);
    let (sk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("MS signature on 10 elements", |b| {
        b.iter(|| {
            ms_sign_messages(&message, &scheme, &sk);
        })
    });
}

// pub fn ms_verify_1_attributes(c: &mut Criterion) {
//     let scheme = MercurialSignatureScheme::new(1);
//     let (sk, pk) = scheme.key_gen();
//     let message = scheme.random_message();
//     let signature = scheme.sign(&sk, &message);
//     c.bench_function("MS signature verification for 1 elements", |b| {
//         b.iter(|| {
//             ms_do_verification(&message, &scheme, &pk, &signature);
//         })
//     });
// }

pub fn ms_verify_2_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(2);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("MS signature verification for 2 elements", |b| {
        b.iter(|| {
            ms_do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn ms_verify_5_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(5);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("MS signature verification for 5 elements", |b| {
        b.iter(|| {
            ms_do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn ms_verify_10_attributes(c: &mut Criterion) {
    let scheme = MercurialSignatureScheme::new(10);
    let (sk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message);
    c.bench_function("MS signature verification for 10 elements", |b| {
        b.iter(|| {
            ms_do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

/* Bench of threshold mercurial signatures, using blstrs library for computations */

// Only checks the pairings
pub fn do_verification(
    message: &Vec<G1Projective>,
    scheme: &DistributedMercurialSignatureScheme,
    pk: &Vec<G2Projective>,
    signature: &DistributedMercurialSignature,
) -> bool {
    scheme.verify(pk, message, signature)
}

// given all element just computes the signature of a message
pub fn sign_messages(
    message: &Vec<G1Projective>,
    scheme: &DistributedMercurialSignatureScheme,
    sk: &Vec<Vec<Scalar>>,
    lpk: &Vec<Vec<G2Projective>>,
) {
    let _signature = scheme.sign(sk, message, lpk);
}

// pub fn sign_1_attributes(c: &mut Criterion) {
//     let scheme = DistributedMercurialSignatureScheme::new(1);
//     let (sk, lpk, _pk) = scheme.key_gen();
//     let message = scheme.random_message();
//     c.bench_function("2P-tms signature on 1 element", |b| {
//         b.iter(|| {
//             sign_messages(&message, &scheme, &sk, &lpk);
//         })
//     });
// }

pub fn sign_2_attributes(c: &mut Criterion) {
    let scheme = DistributedMercurialSignatureScheme::new(2);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("2P-tms signature on 2 elements", |b| {
        b.iter(|| {
            sign_messages(&message, &scheme, &sk, &lpk);
        })
    });
}

pub fn sign_5_attributes(c: &mut Criterion) {
    let scheme = DistributedMercurialSignatureScheme::new(5);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("2P-tms signature on 5 elements", |b| {
        b.iter(|| {
            sign_messages(&message, &scheme, &sk, &lpk);
        })
    });
}

pub fn sign_10_attributes(c: &mut Criterion) {
    let scheme = DistributedMercurialSignatureScheme::new(10);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    c.bench_function("2P-tms signature on 10 elements", |b| {
        b.iter(|| {
            sign_messages(&message, &scheme, &sk, &lpk);
        })
    });
}

// pub fn verify_1_attributes(c: &mut Criterion) {
//     let scheme = DistributedMercurialSignatureScheme::new(1);
//     let (sk, lpk, pk) = scheme.key_gen();
//     let message = scheme.random_message();
//     let signature = scheme.sign(&sk, &message, &lpk);
//     c.bench_function("2P-tms verification on 1 element", |b| {
//         b.iter(|| {
//             do_verification(&message, &scheme, &pk, &signature);
//         })
//     });
// }

pub fn verify_2_attributes(c: &mut Criterion) {
    let scheme = DistributedMercurialSignatureScheme::new(2);
    let (sk, lpk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message, &lpk);
    c.bench_function("2P-tms verification on 2 elements", |b| {
        b.iter(|| {
            do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn verify_5_attributes(c: &mut Criterion) {
    let scheme = DistributedMercurialSignatureScheme::new(5);
    let (sk, lpk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message, &lpk);
    c.bench_function("2P-tms verification on 5 elements", |b| {
        b.iter(|| {
            do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn verify_10_attributes(c: &mut Criterion) {
    let scheme = DistributedMercurialSignatureScheme::new(10);
    let (sk, lpk, pk) = scheme.key_gen();
    let message = scheme.random_message();
    let signature = scheme.sign(&sk, &message, &lpk);
    c.bench_function("2P-tms verification on 10 elements", |b| {
        b.iter(|| {
            do_verification(&message, &scheme, &pk, &signature);
        })
    });
}

pub fn do_tms_verification(
    message: &Vec<G1Projective>,
    scheme: &ThresholdMercurialSignatureScheme,
    vk: &Vec<G2Projective>,
    signature: &ThresholdMercurialSignature,
) -> bool {
    scheme.verify(vk, message, signature)
}

// given all element just computes the signature of a message
pub fn tms_sign_messages(
    message: &Vec<G1Projective>,
    scheme: &ThresholdMercurialSignatureScheme,
    lsk: &Vec<Vec<Scalar>>,
    lvk: &Vec<Vec<G2Projective>>,
    r: &Vec<Scalar>,
    w: &Vec<Scalar>,
    ph: &G1Projective,
    s: &Vec<Scalar>,
    capw: &Vec<G1Projective>,
) {
    let _signature = scheme.sign(message, lsk, lvk, r, w, ph, s, capw);
}

// pub fn tms_sign_5_1_attributes(c: &mut Criterion) {
//     let scheme = ThresholdMercurialSignatureScheme::new(1, 10, 5);
//     let (sk, lpk, _pk) = scheme.key_gen();
//     let message = scheme.random_message();
//     c.bench_function("tms 5 Party Signature on 1 element", |b| {
//         b.iter(|| {
//             tms_sign_messages(&message, &scheme, &sk, &lpk);
//         })
//     });
// }

pub fn tms_sign_5_2_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(2, 10, 5);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    c.bench_function("tms 5 Party Signature on 2 elements", |b| {
        b.iter(|| {
            tms_sign_messages(&message, &scheme, &sk, &lpk, &r, &w, &ph, &s, &capw);
        })
    });
}

pub fn tms_sign_5_5_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(5, 10, 5);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    c.bench_function("tms 5 Party Signature on 5 elements", |b| {
        b.iter(|| {
            tms_sign_messages(&message, &scheme, &sk, &lpk, &r, &w, &ph, &s, &capw);
        })
    });
}

pub fn tms_sign_5_10_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(10, 10, 5);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    c.bench_function("tms 5 Party Signature on 10 elements", |b| {
        b.iter(|| {
            tms_sign_messages(&message, &scheme, &sk, &lpk, &r, &w, &ph, &s, &capw);
        })
    });
}

// pub fn tms_sign_10_1_attributes(c: &mut Criterion) {
//     let scheme = ThresholdMercurialSignatureScheme::new(1, 10, 10);
//     let (sk, lpk, _pk) = scheme.key_gen();
//     let message = scheme.random_message();
//     c.bench_function("tms 10 Party Signature on 1 element", |b| {
//         b.iter(|| {
//             tms_sign_messages(&message, &scheme, &sk, &lpk);
//         })
//     });
// }

pub fn tms_sign_10_2_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(2, 10, 10);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    c.bench_function("tms 10 Party Signature on 2 elements", |b| {
        b.iter(|| {
            tms_sign_messages(&message, &scheme, &sk, &lpk, &r, &w, &ph, &s, &capw);
        })
    });
}

pub fn tms_sign_10_5_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(5, 10, 10);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    c.bench_function("tms 10 Party Signature on 5 elements", |b| {
        b.iter(|| {
            tms_sign_messages(&message, &scheme, &sk, &lpk, &r, &w, &ph, &s, &capw);
        })
    });
}

pub fn tms_sign_10_10_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(10, 10, 10);
    let (sk, lpk, _pk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    c.bench_function("tms 10 Party Signature on 10 elements", |b| {
        b.iter(|| {
            tms_sign_messages(&message, &scheme, &sk, &lpk, &r, &w, &ph, &s, &capw);
        })
    });
}

// pub fn tms_verify_1_attributes(c: &mut Criterion) {
//     let scheme = ThresholdMercurialSignatureScheme::new(1, 10, 5);
//     let (sk, lvk, vk) = scheme.key_gen();
//     let message = scheme.random_message();
//     let signature = scheme.sign(&message, &sk, &lvk);
//     c.bench_function("Verification for tms 5 Party Signature on 1 element", |b| {
//         b.iter(|| {
//             do_tms_verification(&message, &scheme, &vk, &signature);
//         })
//     });
// }

pub fn tms_verify_2_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(2, 10, 5);
    let (sk, lvk, vk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    let signature = scheme.sign(&message, &sk, &lvk, &r, &w, &ph, &s, &capw);
    c.bench_function(
        "Verification for tms 5 Party Signature on 2 elements",
        |b| {
            b.iter(|| {
                do_tms_verification(&message, &scheme, &vk, &signature);
            })
        },
    );
}

pub fn tms_verify_5_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(5, 10, 5);
    let (sk, lvk, vk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    let signature = scheme.sign(&message, &sk, &lvk, &r, &w, &ph, &s, &capw);
    c.bench_function(
        "Verification for tms 5 Party Signature on 5 elements",
        |b| {
            b.iter(|| {
                do_tms_verification(&message, &scheme, &vk, &signature);
            })
        },
    );
}

pub fn tms_verify_10_attributes(c: &mut Criterion) {
    let scheme = ThresholdMercurialSignatureScheme::new(10, 10, 5);
    let (sk, lvk, vk) = scheme.key_gen();
    let message = scheme.random_message();
    let (r, w, ph, s, capw) = scheme.rnd_share_gen();
    let signature = scheme.sign(&message, &sk, &lvk, &r, &w, &ph, &s, &capw);
    c.bench_function(
        "Verification for tms 5 Party Signature on 10 elements",
        |b| {
            b.iter(|| {
                do_tms_verification(&message, &scheme, &vk, &signature);
            })
        },
    );
}

criterion_group!(
    benches,
    ms_sign_2_attributes,
    ms_sign_5_attributes,
    ms_sign_10_attributes,
    ms_verify_2_attributes,
    ms_verify_5_attributes,
    ms_verify_10_attributes,
    sign_2_attributes,
    sign_5_attributes,
    sign_10_attributes,
    tms_sign_5_2_attributes,
    tms_sign_5_5_attributes,
    tms_sign_5_10_attributes,
    tms_sign_10_2_attributes,
    tms_sign_10_5_attributes,
    tms_sign_10_10_attributes,
);

criterion_main!(benches);
