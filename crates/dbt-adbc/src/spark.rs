//! ADBC connection options for Spark

pub const HOST: &str = "spark.host";
pub const PORT: &str = "spark.port";

pub const TRANSPORT_API: &str = "spark.api";
pub mod transport_api {
    pub const THRIFT_BINARY: &str = "thrift+binary";
    pub const THRIFT_HTTP: &str = "thrift+http";
    pub const LIVY: &str = "livy";
    pub const CONNECT: &str = "connect";
}

pub const AUTH_TYPE: &str = "spark.auth_type";
pub mod auth_type {
    // Thrift
    pub const NOSASL: &str = "nosasl";
    pub const PLAIN: &str = "plain";
    pub const LDAP: &str = "ldap";
    pub const KERBEROS: &str = "kerberos";
    // OAuth2 client_credentials; the driver fetches and caches the token
    pub const OIDC: &str = "oidc";

    // Livy
    pub const BASIC: &str = "basic";
    pub const AWS_SIGV4: &str = "aws_sigv4";

    // Spark Connect
    pub const NONE: &str = "none";
    pub const TOKEN: &str = "token";
}

pub const USERNAME: &str = "username";
pub const PASSWORD: &str = "password";

pub const SESSION_CONFIG_PREFIX: &str = "spark.opt.";

pub const KERBEROS_SERVICE_NAME: &str = "spark.kerberos.service_name";

pub const USE_SSL: &str = "spark.use_ssl";

// OIDC (auth_type::OIDC): read by the ADBC Spark driver, which does the token request
pub const OIDC_TOKEN_URL: &str = "spark.oidc.token_url";
pub const OIDC_CLIENT_ID: &str = "spark.oidc.client_id";
pub const OIDC_CLIENT_SECRET: &str = "spark.oidc.client_secret";
pub const OIDC_SCOPE: &str = "spark.oidc.scope";
pub const OIDC_REFRESH_SECONDS: &str = "spark.oidc.refresh_seconds";

// Thrift timeouts, read by the ADBC Spark driver (the driver's own defaults are 60s / 30s)
pub const QUERY_TIMEOUT_SECONDS: &str = "adbc.apache.statement.query_timeout_s";
pub const CONNECT_TIMEOUT_MS: &str = "adbc.spark.connect_timeout_ms";

pub mod livy {
    pub const SESSION_KIND: &str = "spark.livy.session_kind";
    pub mod session_kind {
        pub const SQL: &str = "sql";
        pub const SPARK: &str = "spark";
        pub const PYSPARK: &str = "pyspark";
    }

    pub const SESSION_TTL: &str = "spark.livy.session_ttl";

    pub mod aws {
        pub const REGION: &str = "spark.livy.aws.region";
        pub const EMR_SERVERLESS_EXECUTION_ROLE_ARN: &str =
            "spark.livy.aws.emr_serverless.execution_role_arn";
    }
}
