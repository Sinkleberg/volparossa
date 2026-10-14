//! Typed quote-only framing. Raw report bytes never enter public job JSON/transcripts.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};

use super::super::{
    EXCHANGE_SECONDS, FRAME_OVERHEAD,
    guest::{MAX_QUOTE_REQUEST_BYTES, MAX_QUOTE_RESPONSE_BYTES, QuoteRequest, QuoteResponse},
    protocol::{self, Kind, Purpose, Record},
};
use super::{QuoteError, SELECTOR_OPERATION, SELECTOR_VERSION};

/// A unique challenge authenticated under the fixed quote signing purpose.
pub struct QuoteChallenge(Record);

/// Select quotes on this exact protected stream and authenticate its provider.
///
/// # Errors
/// Rejects wrong providers, purpose, framing or original expiry; no fallback socket.
pub async fn begin<S>(stream: &mut S, provider: &[u8; 32]) -> Result<QuoteChallenge, QuoteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(Duration::from_secs(EXCHANGE_SECONDS), async {
        super::super::super::write_frame(
            stream,
            &super::super::super::Selector {
                version: SELECTOR_VERSION,
                operation: SELECTOR_OPERATION,
                manifest_id: Vec::new(),
            },
        )
        .await
        .map_err(|_| QuoteError::Invalid)?;
        let bytes = protocol::read(stream, FRAME_OVERHEAD).await?;
        let record =
            Record::decode_for(&bytes, Kind::Challenge, protocol::now()?, Purpose::QuoteV1)?;
        if &record.sender() != provider {
            return Err(QuoteError::Unauthorized);
        }
        Ok(QuoteChallenge(record))
    })
    .await
    .map_err(|_| QuoteError::Expired)?
}

/// Exchange a fresh canonical verifier challenge, never a task or arbitrary RPC.
/// Returned bytes still require the live verifier's full evidence checks.
///
/// # Errors
/// Rejects signature/purpose/request substitution, malformed quote binding or expiry.
pub async fn exchange<S>(
    stream: &mut S,
    challenge: QuoteChallenge,
    requester: &SigningKey,
    request: &QuoteRequest,
) -> Result<QuoteResponse, QuoteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(Duration::from_secs(EXCHANGE_SECONDS), async {
        let record =
            Record::request(requester, &challenge.0, request.encode(), protocol::now()?)?;
        let bytes = record.encode();
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        protocol::write(stream, &bytes, MAX_QUOTE_REQUEST_BYTES + FRAME_OVERHEAD).await?;
        let bytes = protocol::read(stream, MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD).await?;
        let reply = Record::decode_for(&bytes, Kind::Reply, protocol::now()?, Purpose::QuoteV1)?;
        reply.matches_challenge(&challenge.0)?;
        if reply.sender() != challenge.0.sender()
            || reply.request_hash() != hash
            || reply.created() < record.created()
        {
            return Err(QuoteError::Unauthorized);
        }
        Ok(QuoteResponse::decode(reply.payload(), request)?)
    })
    .await
    .map_err(|_| QuoteError::Expired)?
}

/// Read one canonical request on the explicitly upgraded local socket.
///
/// # Errors
/// Rejects oversize lengths before allocation and noncanonical payloads.
pub async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<QuoteRequest, QuoteError> {
    Ok(QuoteRequest::decode(
        &protocol::read(stream, MAX_QUOTE_REQUEST_BYTES).await?,
    )?)
}

/// Write one typed request on the explicitly upgraded local socket.
///
/// # Errors
/// Rejects write failure or invalid bounds; the caller owns the deadline.
pub async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &QuoteRequest,
) -> Result<(), QuoteError> {
    Ok(protocol::write(stream, &request.encode(), MAX_QUOTE_REQUEST_BYTES).await?)
}

/// Read a quote against the exact original local request, without exporting it.
///
/// # Errors
/// Rejects oversize, noncanonical or differently bound evidence.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    request: &QuoteRequest,
) -> Result<QuoteResponse, QuoteError> {
    Ok(QuoteResponse::decode(
        &protocol::read(stream, MAX_QUOTE_RESPONSE_BYTES).await?,
        request,
    )?)
}

/// Write identifying evidence only to the explicitly authorized local connection.
///
/// # Errors
/// Rejects write failure or invalid bounds; the caller owns the deadline.
pub async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: &QuoteResponse,
) -> Result<(), QuoteError> {
    Ok(protocol::write(stream, &response.encode(), MAX_QUOTE_RESPONSE_BYTES).await?)
}
