// TODO remove allow oncce live
#[allow(dead_code)]
mod login_routes;
#[allow(dead_code)]
pub mod org_routes;
mod validation;

pub use login_routes::router as login_routes;
pub use org_routes::router as org_routes;
