use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::reqwest::async_http_client;
use oauth2::{AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, TokenResponse, TokenUrl};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let realm_code = std::env::args()
        .nth(1)
        .expect("Expected exactly 1 argument");
    let client_id = std::env::var("CLIENT_ID").expect("Expected client_id in environment");
    let mut headers = HeaderMap::new();
    headers.append("Content-Type", HeaderValue::from_static("application/json"));
    headers.append("Accept", HeaderValue::from_static("application/json"));
    let client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .build()?;
    let device_auth_url = DeviceAuthorizationUrl::new(
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode".to_string(),
    )?;
    let oauth_client = BasicClient::new(
        ClientId::new(client_id),
        None,
        AuthUrl::new(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize".to_string(),
        )?,
        Some(TokenUrl::new(
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/token".to_string(),
        )?),
    )
    .set_device_authorization_url(device_auth_url);

    let details: StandardDeviceAuthorizationResponse = oauth_client
        .exchange_device_code()?
        .add_scope(Scope::new("XboxLive.signin".to_string()))
        .request_async(async_http_client)
        .await?;

    eprintln!(
        "Open this URL in your browser:\n{}\nand enter the code: {}",
        **details.verification_uri(),
        details.user_code().secret()
    );

    let token_result = oauth_client
        .exchange_device_access_token(&details)
        .request_async(
            async_http_client,
            tokio::time::sleep,
            Some(std::time::Duration::from_secs(300)),
        )
        .await?;
    let xbl_auth = XblAuth {
        properties: XblAuthProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket: format!("d={}", token_result.access_token().secret()),
        },
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
    };
    let xbl_response: XblAuthResponse = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .json(&xbl_auth)
        .send()
        .await?
        .json()
        .await?;
    let xsts_auth = XSTSRequest {
        properties: XSTSProperties {
            sandbox_id: "RETAIL".to_string(),
            user_tokens: vec![xbl_response.token],
        },
        relying_party: "https://pocket.realms.minecraft.net/".to_string(),
        token_type: "JWT".to_string(),
    };
    let xsts_response: XstsResponse = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .json(&xsts_auth)
        .send()
        .await?
        .json()
        .await?;
    let service_token = format!(
        "XBL3.0 x={};{}",
        xsts_response.display_claims.xui[0].uhs, xsts_response.token
    );
    let mut headers = HeaderMap::new();
    headers.append("Accept", HeaderValue::from_static("*/*"));
    headers.append("Authorization", HeaderValue::from_str(&service_token)?);
    headers.append("User-Agent", HeaderValue::from_static("MCPE/UWP"));
    headers.append("Client-Version", HeaderValue::from_static("1.20.10"));
    headers.append("Accept-Language", HeaderValue::from_static("en-GB,en"));
    let client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .build()?;
    let req = client
        .get(format!(
            "https://pocket.realms.minecraft.net/worlds/v1/link/{realm_code}"
        ))
        .send()
        .await?;
    let status = req.status();
    let data = req.text().await?;
    if status.is_success() {
        let realm: Realm = serde_json::from_str(&data)?;
        println!("{realm:#?}");
    } else if status.is_client_error() {
        println!("Client error {status}:");
        println!("{data}");
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Realm {
    pub id: i64,
    pub remote_subscription_id: String,
    pub owner: Option<String>,
    #[serde(rename = "ownerUUID")]
    pub owner_xuid: String,
    pub name: String,
    pub motd: String,
    pub default_permission: RealmPermission,
    pub state: RealmState,
    pub club_id: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RealmState {
    Open,
    Closed,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RealmPermission {
    Visitor,
    Member,
    Operator,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XblAuth {
    #[serde(rename = "Properties")]
    pub properties: XblAuthProperties,
    #[serde(rename = "RelyingParty")]
    pub relying_party: String,
    #[serde(rename = "TokenType")]
    pub token_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XblAuthProperties {
    #[serde(rename = "AuthMethod")]
    pub auth_method: String,
    #[serde(rename = "SiteName")]
    pub site_name: String,
    #[serde(rename = "RpsTicket")]
    pub rps_ticket: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XblAuthResponse {
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "NotAfter")]
    pub not_after: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "DisplayClaims")]
    pub display_claims: DisplayClaims,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplayClaims {
    pub xui: Vec<Xui>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Xui {
    pub uhs: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XSTSRequest {
    #[serde(rename = "Properties")]
    pub properties: XSTSProperties,
    #[serde(rename = "RelyingParty")]
    pub relying_party: String,
    #[serde(rename = "TokenType")]
    pub token_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XSTSProperties {
    #[serde(rename = "SandboxId")]
    pub sandbox_id: String,
    #[serde(rename = "UserTokens")]
    pub user_tokens: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XstsResponse {
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "NotAfter")]
    pub not_after: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "DisplayClaims")]
    pub display_claims: DisplayClaims,
}
