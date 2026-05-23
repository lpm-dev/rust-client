use std::env;

fn usage() -> ! {
    eprintln!(
        "usage: cargo run -p lpm-auth --example seed_refresh_backed_session -- <registry-url> <access-token> <refresh-token> <expires-at>"
    );
    std::process::exit(2);
}

fn main() {
    let mut args = env::args().skip(1);
    let registry_url = args.next().unwrap_or_else(|| usage());
    let access_token = args.next().unwrap_or_else(|| usage());
    let refresh_token = args.next().unwrap_or_else(|| usage());
    let expires_at = args.next().unwrap_or_else(|| usage());

    if args.next().is_some() {
        usage();
    }

    lpm_auth::set_token(&registry_url, &access_token)
        .unwrap_or_else(|error| panic!("failed to store access token: {error}"));
    lpm_auth::set_refresh_token(&registry_url, &refresh_token);
    lpm_auth::set_session_access_token_expiry(&registry_url, &expires_at);
}
