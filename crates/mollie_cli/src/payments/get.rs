use colored::Colorize;
use mollie_api::Mollie;
use log::{debug, info};
use crate::payments::Payment;

pub async fn command(payment_id: &String) -> anyhow::Result<()>{
    debug!("Running Get API Payment for payment: {}", payment_id);

    let token = super::config::get_bearer_token().unwrap();

    let payment = Mollie::build(&token.value).payments().get_by_id(payment_id).await;

    debug!("{:?}", payment);
    match payment {
        Ok(p) => {
            info!("{}", Colorize::bright_black(&*Payment::header()));
            info!("{}", Payment::from(p.clone()).to_string());
        },
        Err(e) => info!("{}", e), 
    }
    /*info!(
        "{} | {} | {} {} | {}",
        payment.id, payment.mode, payment.amount.value, payment.amount.currency, payment.status
    );
    */
   

    return Ok(());
}
