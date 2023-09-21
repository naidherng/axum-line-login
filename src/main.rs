//! Example OAuth (Line) implementation.
//!
//! 1) Create a new application at <https://developers.line.biz/en/docs/line-login/integrate-line-login/>
//! 2) Visit the OAuth2 tab to get your CLIENT_ID and CLIENT_SECRET
//! 3) Add a new redirect URI (for this example: `http://192.168.1.100/auth/authorized`)
//! 4) Run with the following (replacing values appropriately):
//! ```not_rust
//! CLIENT_ID=REPLACE_ME CLIENT_SECRET=REPLACE_ME cargo run
//! ```

use anyhow::{ Context, Result };
use async_session::{ MemoryStore, Session, SessionStore };
use axum::{
    async_trait,
    extract::{
        FromRef,
        FromRequestParts,
        Query,
        State,
        rejection::TypedHeaderRejectionReason,
        MatchedPath,
    },
    http::{ header::SET_COOKIE, HeaderMap },
    response::{ IntoResponse, Redirect, Response },
    routing::get,
    RequestPartsExt,
    Router,
    TypedHeader,
    headers,
    body::Bytes,
};

use http::{ header, request::Parts, StatusCode, Request };
use oauth2::{
    basic::{
        BasicErrorResponse,
        BasicTokenType,
        BasicTokenIntrospectionResponse,
        BasicRevocationErrorResponse,
    },
    reqwest::async_http_client,
    AuthUrl,
    AuthorizationCode,
    ClientId,
    ClientSecret,
    CsrfToken,
    RedirectUrl,
    Scope,
    TokenUrl,
    ExtraTokenFields,
    Client,
    StandardRevocableToken,
    StandardTokenResponse,
};
use serde::{ Deserialize, Serialize };
use tower_http::{ classify::ServerErrorsFailureClass, trace::TraceLayer };
use tracing::{ Span, info_span };
use std::{ env, time::Duration, net::SocketAddr };
use tracing_subscriber::{ layer::SubscriberExt, util::SubscriberInitExt };

static COOKIE_NAME: &str = "SESSION";

#[tokio::main]
async fn main() {
    tracing_subscriber
        ::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                "line_login=debug,tower_http=debug,axum::rejection=trace".into()
            })
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();
    let oauth_client = oauth_client().unwrap();

    let app_state = AppState {
        store,
        oauth_client,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/line", get(line_auth))
        .route("/auth/authorized", get(login_authorized))
        .route("/protected", get(protected))
        .route("/logout", get(logout))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    // Log the matched route's path (with placeholders not filled in).
                    // Use request.uri() or OriginalUri if you want the real path.
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);

                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                        some_other_field = tracing::field::Empty,
                    )
                })
                .on_request(
                    |_request: &Request<_>, _span: &Span| {
                        // You can use `_span.record("some_other_field", value)` in one of these
                        // closures to attach a value to the initially empty field in the info_span
                        // created above.
                    }
                )
                .on_response(
                    |_response: &Response, _latency: Duration, _span: &Span| {
                        // ...
                    }
                )
                .on_body_chunk(
                    |_chunk: &Bytes, _latency: Duration, _span: &Span| {
                        // ...
                    }
                )
                .on_eos(
                    |_trailers: Option<&HeaderMap>, _stream_duration: Duration, _span: &Span| {
                        // ...
                    }
                )
                .on_failure(
                    |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                        // ...
                    }
                )
        )
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 30003));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
    oauth_client: LineClient,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for LineClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

///
/// Implement ExtraFiled
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LineExtraTokenFields {
    id_token: String,
}
impl ExtraTokenFields for LineExtraTokenFields {}

type TokenLineResponse = StandardTokenResponse<LineExtraTokenFields, BasicTokenType>;

type LineClient = Client<
    BasicErrorResponse,
    TokenLineResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse
>;

fn oauth_client() -> Result<LineClient, AppError> {
    // Environment variables (* = required):
    // *"CLIENT_ID"     "REPLACE_ME";
    // *"CLIENT_SECRET" "REPLACE_ME";
    //  "REDIRECT_URL"  "http://192.168.200.123:30003/auth/authorized";
    //  "AUTH_URL"      "https://access.line.me/oauth2/v2.1/authorize?response_type=code";
    //  "TOKEN_URL"     "https://api.line.me/oauth2/v2.1/token";

    //let st = StandardTokenResponse::new(access_token, token_type, extra_fields);

    let client_id = env::var("CLIENT_ID").context("Missing CLIENT_ID!")?;
    let client_secret = env::var("CLIENT_SECRET").context("Missing CLIENT_SECRET!")?;
    let redirect_url = env
        ::var("REDIRECT_URL")
        .unwrap_or_else(|_| "http://192.168.200.123:30003/auth/authorized".to_string());

    let auth_url = env
        ::var("AUTH_URL")
        .unwrap_or_else(|_| {
            "https://access.line.me/oauth2/v2.1/authorize?response_type=code".to_string()
        });

    let token_url = env
        ::var("TOKEN_URL")
        .unwrap_or_else(|_| "https://api.line.me/oauth2/v2.1/token".to_string());

    Ok(
        LineClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_url).context("failed to create new authorization server URL")?,
            Some(TokenUrl::new(token_url).context("failed to create new token endpoint URL")?)
        ).set_redirect_uri(
            RedirectUrl::new(redirect_url).context("failed to create new redirection URL")?
        )
    )
}

// The user data we'll get back from Line.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    iss: String,
    aud: String,
    exp: u32,
    iat: u32,
    sub: String,
    nonce: String,
    name: String,
    picture: String,
}

// Session is optional
async fn index(user: Option<User>) -> impl IntoResponse {
    match user {
        Some(u) =>
            format!(
                "Hey {}! You're logged in!\nYou may now access `/protected`.\nLog out with `/logout`.",
                u.name
            ),
        None => "You're not logged in.\nVisit `/auth/line` to do so.".to_string(),
    }
}

async fn line_auth(State(client): State<LineClient>) -> impl IntoResponse {
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .add_extra_param("nonce", CsrfToken::new_random().secret())
        .url();

    // Redirect to Line's oauth service
    Redirect::to(auth_url.as_ref())
}

// Valid user session required. If there is none, redirect to the auth page
async fn protected(user: User) -> impl IntoResponse {
    format!("Welcome to the protected area :)\nHere's your info:\n{user:?}")
}

async fn logout(
    State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>
) -> Result<impl IntoResponse, AppError> {
    let cookie = cookies.get(COOKIE_NAME).context("unexpected error getting cookie name")?;

    let session = match
        store.load_session(cookie.to_string()).await.context("failed to load session")?
    {
        Some(s) => s,
        // No session active, just redirect
        None => {
            return Ok(Redirect::to("/"));
        }
    };

    store.destroy_session(session).await.context("failed to destroy session")?;
    tracing::debug!("Logout success.");
    Ok(Redirect::to("/"))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn login_authorized(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(oauth_client): State<LineClient>
) -> Result<impl IntoResponse, AppError> {
    // Get an auth token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client).await
        .context("failed in sending request request to authorization server")?;

    tracing::debug!("TOKEN: {:?}", token.clone());

    // Fetch user data from line
    let verrify_parms = [
        ("id_token", token.extra_fields().id_token.to_owned()),
        ("client_id", oauth_client.client_id().to_string()),
    ];

    let client = reqwest::Client::new();
    let user_data: User = client
        .post("https://api.line.me/oauth2/v2.1/verify")
        .form(&verrify_parms)
        .send().await
        .context("failed in sending request to target Url")?
        .json::<User>().await
        .context("failed to deserialize response as JSON")?;

    tracing::debug!("USER: {:?}", user_data.clone());
    // Create a new session filled with user data
    let mut session = Session::new();
    session
        .insert("user", &user_data)
        .context("failed in inserting serialized value into session")?;

    // Store session and get corresponding cookie
    let cookie = store
        .store_session(session).await
        .context("failed to store session")?
        .context("unexpected error retrieving cookie value")?;

    // Build the cookie
    let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().context("failed to parse cookie")?);

    Ok((headers, Redirect::to("/")))
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/line").into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for User where MemoryStore: FromRef<S>, S: Send + Sync {
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);

        let cookies = parts.extract::<TypedHeader<headers::Cookie>>().await.map_err(|e| {
            match *e.name() {
                header::COOKIE =>
                    match e.reason() {
                        TypedHeaderRejectionReason::Missing => AuthRedirect,
                        _ => panic!("unexpected error getting Cookie header(s): {e}"),
                    }
                _ => panic!("unexpected error getting cookies: {e}"),
            }
        })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string()).await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let user = session.get::<User>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

// Use anyhow, define error and enable '?'
// For a simplified example of using anyhow in axum check /examples/anyhow-error-response
#[derive(Debug)]
struct AppError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.0);

        (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError where E: Into<anyhow::Error> {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
