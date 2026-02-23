use std::env;

use aws_sdk_kms::Client;
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

use passkms_core::{Authenticator, CredentialStore, GetAssertionRequest, MakeCredentialRequest};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = Client::new(&config);
    let store = CredentialStore::new(kms_client);
    let authenticator = Authenticator::new(store);

    match command {
        "register" => {
            let rp_id = args.get(2).map(String::as_str).unwrap_or("example.com");
            let user_name = args.get(3).map(String::as_str).unwrap_or("testuser");
            register(&authenticator, rp_id, user_name).await;
        }
        "authenticate" => {
            let rp_id = args.get(2).map(String::as_str).unwrap_or("example.com");
            let credential_id = args.get(3).map(String::as_str);
            authenticate(&authenticator, rp_id, credential_id).await;
        }
        "list" => {
            let rp_id = args.get(2).map(String::as_str).unwrap_or("example.com");
            list_credentials(&authenticator, rp_id).await;
        }
        _ => {
            eprintln!("Usage: passkms-server <command> [args...]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  register [rp_id] [user_name]     Register a new credential");
            eprintln!("  authenticate [rp_id] [cred_id]   Authenticate with a credential");
            eprintln!("  list [rp_id]                      List credentials for an RP");
        }
    }
}

async fn register(authenticator: &Authenticator, rp_id: &str, user_name: &str) {
    println!("Registering credential for RP: {rp_id}, user: {user_name}");

    // Simulate client data hash (in real flow, this comes from the browser)
    let client_data_hash: [u8; 32] = Sha256::digest(b"fake-client-data-for-testing").into();

    let request = MakeCredentialRequest {
        client_data_hash,
        rp_id: rp_id.to_string(),
        rp_name: Some(rp_id.to_string()),
        user_handle: user_name.as_bytes().to_vec(),
        user_name: Some(user_name.to_string()),
        user_display_name: Some(user_name.to_string()),
        user_presence: false, // No user presence verification in headless mode
        exclude_list: vec![],
        pub_key_cred_params: vec![-7], // ES256
    };

    match authenticator.make_credential(&request).await {
        Ok(response) => {
            let cred_id = String::from_utf8_lossy(&response.credential_id);
            println!("Registration successful!");
            println!("  Credential ID: {cred_id}");
            println!(
                "  Auth data length: {} bytes",
                response.auth_data_bytes.len()
            );
            println!(
                "  Attestation object length: {} bytes",
                response.attestation_object.len()
            );
        }
        Err(e) => {
            eprintln!("Registration failed: {e}");
            std::process::exit(1);
        }
    }
}

async fn authenticate(authenticator: &Authenticator, rp_id: &str, credential_id: Option<&str>) {
    println!("Authenticating for RP: {rp_id}");

    let client_data_hash: [u8; 32] = Sha256::digest(b"fake-client-data-for-auth").into();

    let allow_list = match credential_id {
        Some(id) => {
            println!("  Using credential: {id}");
            vec![id.as_bytes().to_vec()]
        }
        None => {
            println!("  Using discoverable credentials");
            vec![]
        }
    };

    let request = GetAssertionRequest {
        rp_id: rp_id.to_string(),
        client_data_hash,
        user_presence: false, // No user presence verification in headless mode
        allow_list,
    };

    match authenticator.get_assertion(&request).await {
        Ok(responses) => {
            println!(
                "Authentication successful! {} assertion(s):",
                responses.len()
            );
            for (i, response) in responses.iter().enumerate() {
                let cred_id = String::from_utf8_lossy(&response.credential_id);
                println!("  Assertion {i}:");
                println!("    Credential ID: {cred_id}");
                println!(
                    "    Auth data length: {} bytes",
                    response.auth_data_bytes.len()
                );
                println!("    Signature length: {} bytes", response.signature.len());
                if let Some(ref uh) = response.user_handle {
                    println!("    User handle: {}", hex::encode(uh));
                }
            }
        }
        Err(e) => {
            eprintln!("Authentication failed: {e}");
            std::process::exit(1);
        }
    }
}

async fn list_credentials(authenticator: &Authenticator, rp_id: &str) {
    println!("Listing credentials for RP: {rp_id}");

    match authenticator.store().discover_credentials(rp_id).await {
        Ok(credentials) => {
            if credentials.is_empty() {
                println!("  No credentials found");
            } else {
                for cred in &credentials {
                    println!("  Key ID: {}", cred.key_id);
                    if let Some(ref name) = cred.user_name {
                        println!("    User name: {name}");
                    }
                    if let Some(ref name) = cred.display_name {
                        println!("    Display name: {name}");
                    }
                    if let Some(ref rp) = cred.rp_id {
                        println!("    RP ID: {rp}");
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to list credentials: {e}");
            std::process::exit(1);
        }
    }
}
