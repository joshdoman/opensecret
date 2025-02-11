// @generated automatically by Diesel CLI.

diesel::table! {
    email_verifications (id) {
        id -> Int4,
        user_id -> Uuid,
        verification_code -> Uuid,
        is_verified -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    enclave_secrets (id) {
        id -> Int4,
        key -> Text,
        value -> Bytea,
    }
}

diesel::table! {
    oauth_providers (id) {
        id -> Int4,
        #[max_length = 255]
        name -> Varchar,
        auth_url -> Text,
        token_url -> Text,
        user_info_url -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    password_reset_requests (id) {
        id -> Int4,
        user_id -> Uuid,
        #[max_length = 255]
        hashed_secret -> Varchar,
        encrypted_code -> Bytea,
        expiration_time -> Timestamptz,
        created_at -> Timestamptz,
        is_reset -> Bool,
    }
}

diesel::table! {
    token_usage (id) {
        id -> Int8,
        user_id -> Uuid,
        input_tokens -> Int4,
        output_tokens -> Int4,
        estimated_cost -> Numeric,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_kv (id) {
        id -> Int8,
        user_id -> Uuid,
        key_enc -> Bytea,
        value_enc -> Bytea,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_oauth_connections (id) {
        id -> Int4,
        user_id -> Uuid,
        provider_id -> Int4,
        #[max_length = 255]
        provider_user_id -> Varchar,
        access_token_enc -> Bytea,
        refresh_token_enc -> Nullable<Bytea>,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        uuid -> Uuid,
        name -> Nullable<Text>,
        email -> Nullable<Citext>,
        password_enc -> Nullable<Bytea>,
        seed_enc -> Nullable<Bytea>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(user_oauth_connections -> oauth_providers (provider_id));

diesel::allow_tables_to_appear_in_same_query!(
    email_verifications,
    enclave_secrets,
    oauth_providers,
    password_reset_requests,
    token_usage,
    user_kv,
    user_oauth_connections,
    users,
);
