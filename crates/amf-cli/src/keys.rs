//! `amf keygen`.

use anyhow::{Context, Result};

use crate::ui;
use crate::KeygenArgs;

pub fn run(args: KeygenArgs) -> Result<()> {
    let public =
        amf_verify::generate_keypair(&args.secret, &args.public, args.password, &args.comment)
            .with_context(|| format!("generating a keypair at {}", args.secret.display()))?;

    ui::step("signing keypair generated");
    ui::info(&format!("  secret key: {}", args.secret.display()));
    ui::info(&format!("  public key: {}", args.public.display()));
    ui::info(&format!("  key:        {public}"));
    ui::info("");
    ui::info("Copy the PUBLIC key to the airgapped machine — it is what verifies");
    ui::info("bundles there. Keep the secret key on this machine only: anyone");
    ui::info("holding it can produce a bundle the airgapped side will accept.");
    Ok(())
}
