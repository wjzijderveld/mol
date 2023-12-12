use crate::config::MollieConfig;
use std::sync::Arc;

use colored_json::ToColoredJson;
use log::info;
use mollie_api::{models::permission::PermissionsEmbeddedResource, Mollie};
use pad::{Alignment, PadStr};

pub async fn command(
    config: &MollieConfig,
    filter_granted: &bool,
    with_response: bool,
) -> miette::Result<()> {
    let permissions = Mollie::build(&config.bearer_token()?.as_str())
        .permissions()
        .list()
        .await?;

    if *filter_granted {
        list_granted_permissions(&permissions.embedded)
    } else {
        list_permissions(&permissions.embedded);
    }

    if with_response {
        let pretty_json =
            jsonxf::pretty_print(&serde_json::to_string(&permissions).unwrap()).unwrap();
        info!("{}", pretty_json.to_colored_json_auto().unwrap());
    }

    Ok(())
}

fn list_permissions(permissions: &PermissionsEmbeddedResource) {
    for permission in permissions.clone().permissions {
        info!(
            "{} | Granted: {} | {}",
            permission
                .id
                .pad_to_width_with_alignment(20, Alignment::Right),
            permission.granted as i32,
            permission.description
        );
    }
}

fn list_granted_permissions(permissions: &PermissionsEmbeddedResource) {
    for permission in permissions.clone().permissions {
        if permission.granted {
            info!(
                "{} | {}",
                permission
                    .id
                    .pad_to_width_with_alignment(20, Alignment::Right),
                permission.description
            );
        }
    }
}
