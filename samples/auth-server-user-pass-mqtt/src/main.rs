// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Handles authentication of MQTT connections.
mod authenticate;

/// Handles parsing and generating HTTP requests.
mod http;

use anyhow::Result;
use clap::Parser;
use env_logger;
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use openssl::{
    pkey::{PKey, Private},
    ssl::{Ssl, SslAcceptor, SslContext, SslMethod, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use std::{net::TcpListener, path::PathBuf, pin::Pin};
use tokio_openssl::SslStream;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging.
    env_logger::init();
    info!("Initiating authentication server for username password...");

    let options = Options::parse();

    info!("Configuring TLS for secure communication...");
    let server_key = std::fs::read(&options.server_key)?;
    let server_key = PKey::private_key_from_pem(&server_key)?;
    let server_cert_chain = std::fs::read(&options.server_cert_chain)?;
    let server_cert_chain = X509::stack_from_pem(&server_cert_chain)?;

    let client_cert_issuer = if let Some(path) = options.client_cert_issuer {
        let certs = std::fs::read(path)?;
        let certs = X509::stack_from_pem(&certs)?;

        Some(certs)
    } else {
        None
    };

    let tls_context = tls_context(server_cert_chain, &server_key, client_cert_issuer)?;

    info!("Initiating to listen on 0.0.0.0:{}...", options.port);

    // Start listening for incoming connections.
    let tcp_listener = TcpListener::bind(("0.0.0.0", options.port))?;
    tcp_listener.set_nonblocking(true)?;
    let tcp_listener = tokio::net::TcpListener::from_std(tcp_listener)?;

    // Accept incoming connections and process them.
    loop {
        let (stream, _) = tcp_listener.accept().await?;
        let ssl = Ssl::new(&tls_context).expect("invalid TLS context");
        let mut stream = match SslStream::new(ssl, stream) {
            Ok(stream) => stream,
            Err(err) => {
                error!("Failed to create SSLStream: {err}");

                continue;
            }
        };

        if let Err(err) = Pin::new(&mut stream).accept().await {
            error!("Failed to establish TLS connection: {err}");

            continue;
        }

        let stream = TokioIo::new(stream);

        tokio::spawn(async move {
            if let Err(err) = ServerBuilder::new()
                .serve_connection(stream, hyper::service::service_fn(process_req))
                .await
            {
                info!("HTTP server error: {err:?}");
            }
        });
    }
}

/// Command-line options for this program.
#[derive(Parser)]
struct Options {
    /// Port to listen on.
    #[arg(long, short, value_name = "PORT")]
    port: u16,

    /// TLS server cert chain to present to connecting clients.
    #[arg(long, short = 'c', value_name = "SERVER_CERT_CHAIN")]
    server_cert_chain: PathBuf,

    /// Private key of TLS server cert.
    #[arg(long, short = 'k', value_name = "SERVER_KEY")]
    server_key: PathBuf,

    /// Optional CA certs for validating client certificates. Omit to disable
    /// client certificate validation.
    #[arg(long, short = 'i', value_name = "CLIENT_CERT_ISSUER")]
    client_cert_issuer: Option<PathBuf>,
}

/// Create a TLS context from the given X.509 credentials.
fn tls_context(
    server_cert_chain: Vec<X509>,
    private_key: &PKey<Private>,
    client_cert_issuer: Option<Vec<X509>>,
) -> Result<SslContext> {
    let mut tls_acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    tls_acceptor.set_private_key(private_key)?;

    let mut server_cert_chain = server_cert_chain.into_iter();

    if let Some(leaf_cert) = server_cert_chain.next() {
        tls_acceptor.set_certificate(&leaf_cert)?;
    } else {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no certs provided").into(),
        );
    }

    if let Some(issuer) = client_cert_issuer {
        let mut store = X509StoreBuilder::new()?;

        for cert in issuer {
            store.add_cert(cert)?;
        }

        tls_acceptor.set_verify_cert_store(store.build())?;
        tls_acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }

    for cert in server_cert_chain {
        tls_acceptor.add_extra_chain_cert(cert)?;
    }

    let tls_acceptor = tls_acceptor.build();

    Ok(tls_acceptor.into_context())
}

/// Parse an HTTP request and authenticate the connecting client.
async fn process_req(
    req: http::HttpRequest,
) -> Result<http::HttpResponse, std::convert::Infallible> {
    let req = match http::ParsedRequest::from_http(req).await {
        Ok(req) => req,
        Err(response) => return Ok(response.to_http()),
    };

    // TODO: Review this debug statement from SFI perspective.
    // This prints the incoming HTTP request. Useful for debugging, but note that
    // it may print sensitive data.
    debug!("{req:?}");

    let response = authenticate::authenticate(req).await;

    Ok(response.to_http())
}
