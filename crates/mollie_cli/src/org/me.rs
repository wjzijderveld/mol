use crate::config::MollieConfig;
use mollie_api::Mollie;
use std::sync::Arc;

pub async fn command(config: Arc<MollieConfig>) -> anyhow::Result<()> {
    let token = config.bearer_token().unwrap();
    let response = Mollie::build(token.as_str()).organizations().me().await?;
    println!("Organization: {:#?}", response.id);
    println!("{:#?}", response);
    Ok(())
}
