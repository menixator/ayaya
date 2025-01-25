use anyhow::Context;
use sqlx::PgPool;
use tonic::{transport::Server, Request, Response, Status};

mod grpc;

use grpc::{
    ayaya_trace_collection_server::{AyayaTraceCollection, AyayaTraceCollectionServer},
    CollectRequest, CollectionReply, Trace,
};

#[derive(Debug)]
pub struct TraceCollector {
    pool: PgPool,
}

#[tonic::async_trait]
impl AyayaTraceCollection for TraceCollector {
    async fn collect(
        &self,
        request: tonic::Request<CollectRequest>,
    ) -> std::result::Result<tonic::Response<CollectionReply>, tonic::Status> {
        let message = request.get_ref();
        let mut count = 0;
        // TODO: Do a bulk insert
        for trace in message.traces.iter() {
            let trace_timestamp = if let Some(timestamp) = trace.timestamp {
                timestamp
            } else {
                continue;
            };
            if trace_timestamp.nanos < 0 {
                continue;
            }

            let timestamp = time::OffsetDateTime::from_unix_timestamp(trace_timestamp.seconds)
                .map_err(|_| {
                    tonic::Status::new(tonic::Code::InvalidArgument, "timestamp is invalid")
                })?;
            let timestamp = timestamp
                .replace_nanosecond(trace_timestamp.nanos as u32)
                .map_err(|_| {
                    tonic::Status::new(tonic::Code::InvalidArgument, "timestamp is invalid")
                })?;

            sqlx::query!(
                "INSERT INTO 
                events(
                    timestamp,
                    username,
                    groupname,
                    event,
                    path,
                    path_secondary
                )
                VALUES($1, $2, $3, $4, $5, $6)",
                timestamp,
                trace.username,
                trace.groupname,
                trace.event,
                trace.path,
                trace.path_secondary,
            )
            .execute(&self.pool)
            .await
            .map_err(|_| tonic::Status::new(tonic::Code::Internal, "failed"))?;

            count += 1;
        }
        Ok(tonic::Response::new(CollectionReply { count }))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let pool =
        PgPool::connect(&std::env::var("DATABASE_URL").with_context(|| "DATABASE_URL is not set")?)
            .await?;

    // TODO: the migrations along with this macro will be moved to the backend
    sqlx::migrate!("../migrations").run(&pool).await?;
    let addr = std::env::var("AYAYA_COLLECTOR")
        .with_context(|| "AYAYA_COLLECTOR env variable is not set")?
        .parse()?;
    let service = TraceCollector { pool };

    Server::builder()
        .add_service(AyayaTraceCollectionServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
