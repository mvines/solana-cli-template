use {
    clap::{crate_description, crate_name, crate_version, Arg, Command},
    solana_clap_v3_utils::{
        input_parsers::pubkey_of,
        input_validators::{
            is_url_or_moniker, is_valid_pubkey, is_valid_signer, normalize_to_url_if_moniker,
        },
        keypair::DefaultSigner,
    },
    solana_client::rpc_client::RpcClient,
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        message::Message,
        native_token::Sol,
        signature::{Signature, Signer},
        system_instruction,
        transaction::Transaction,
    },
    std::{process::exit, sync::Arc},
};

struct Config {
    commitment_config: CommitmentConfig,
    default_signer: Box<dyn Signer>,
    json_rpc_url: String,
    verbose: bool,
}

fn process_ping(
    rpc_client: &RpcClient,
    signer: &dyn Signer,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let from = signer.pubkey();
    let to = signer.pubkey();
    let amount = 0;

    let mut transaction = Transaction::new_unsigned(Message::new(
        &[system_instruction::transfer(&from, &to, amount)],
        Some(&signer.pubkey()),
    ));

    let blockhash = rpc_client
        .get_latest_blockhash()
        .map_err(|err| format!("error: unable to get latest blockhash: {}", err))?;

    transaction
        .try_sign(&vec![signer], blockhash)
        .map_err(|err| format!("error: failed to sign transaction: {}", err))?;

    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .map_err(|err| format!("error: send transaction: {}", err))?;

    Ok(signature)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_matches = Command::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg({
            let arg = Arg::new("config_file")
                .short('C')
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::new("keypair")
                .long("keypair")
                .value_name("KEYPAIR")
                .validator(|s| is_valid_signer(s))
                .takes_value(true)
                .global(true)
                .help("Filepath or URL to a keypair [default: client keypair]"),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .takes_value(false)
                .global(true)
                .help("Show additional information"),
        )
        .arg(
            Arg::new("json_rpc_url")
                .short('u')
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .global(true)
                .validator(|s| is_url_or_moniker(s))
                .help("JSON RPC URL for the cluster [default: value from configuration file]"),
        )
        .subcommand(
            Command::new("balance").about("Get balance").arg(
                Arg::new("address")
                    .validator(|s| is_valid_pubkey(s))
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .index(1)
                    .help("Address to get the balance of"),
            ),
        )
        .subcommand(Command::new("ping").about("Send a ping transaction"))
        .get_matches();

    let (command, matches) = app_matches.subcommand().unwrap();
    let mut wallet_manager: Option<Arc<RemoteWalletManager>> = None;

    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };

        let default_signer = DefaultSigner::new(
            "keypair",
            matches
                .value_of(&"keypair")
                .map(|s| s.to_string())
                .unwrap_or_else(|| cli_config.keypair_path.clone()),
        );

        Config {
            json_rpc_url: normalize_to_url_if_moniker(
                matches
                    .value_of("json_rpc_url")
                    .unwrap_or(&cli_config.json_rpc_url),
            ),
            default_signer: default_signer
                .signer_from_path(matches, &mut wallet_manager)
                .unwrap_or_else(|err| {
                    eprintln!("error: {}", err);
                    exit(1);
                }),
            verbose: matches.is_present("verbose"),
            commitment_config: CommitmentConfig::confirmed(),
        }
    };
    solana_logger::setup_with_default("solana=info");

    if config.verbose {
        println!("JSON RPC URL: {}", config.json_rpc_url);
    }
    let rpc_client =
        RpcClient::new_with_commitment(config.json_rpc_url.clone(), config.commitment_config);

    match (command, matches) {
        ("balance", arg_matches) => {
            let address =
                pubkey_of(arg_matches, "address").unwrap_or_else(|| config.default_signer.pubkey());
            println!(
                "{} has a balance of {}",
                address,
                Sol(rpc_client.get_balance(&address)?)
            );
        }
        ("ping", _arg_matches) => {
            let signature = process_ping(&rpc_client, config.default_signer.as_ref())
                .unwrap_or_else(|err| {
                    eprintln!("error: send transaction: {}", err);
                    exit(1);
                });
            println!("Signature: {}", signature);
        }
        _ => unreachable!(),
    };

    Ok(())
}

#[cfg(test)]
mod test {
    use {super::*, solana_validator::test_validator::*};

    #[test]
    fn test_ping() {
        let (test_validator, payer) = TestValidatorGenesis::default().start();
        let rpc_client = test_validator.get_rpc_client();

        assert!(matches!(process_ping(&rpc_client, &payer), Ok(_)));
    }
}
