pub mod attestation_routes;
pub mod encryption_middleware;
mod health_routes;
mod login_routes;
mod oauth_routes;
mod openai;
mod protected_routes;

pub use health_routes::router as health_routes;
pub use login_routes::router as login_routes;
pub use oauth_routes::router as oauth_routes;
pub use openai::router as openai_routes;
pub use protected_routes::router as protected_routes;
