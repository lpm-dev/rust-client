//! The TLS stack's random generator seeds from the operating system.
//! `.cargo/config.toml` builds aws-lc without its CPU-jitter source, which
//! cost about 25 ms inside the first TLS handshake of every process.

#[test]
fn tls_random_generator_seeds_without_sampling_cpu_jitter() {
    assert!(
        aws_lc_rs::try_fips_cpu_jitter_entropy().is_err(),
        "aws-lc was built with CPU jitter entropy; is AWS_LC_SYS_NO_JITTER_ENTROPY set?"
    );
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).expect("the OS-seeded generator produces bytes");
    assert_ne!(bytes, [0u8; 32]);
}
