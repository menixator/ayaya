use tonic::{transport::Server, Request, Response, Status};

pub mod ayaya_collection {
    tonic::include_proto!("ayaya_collection");
}

use ayaya_collection::{
    ayaya_trace_collection_server::{AyayaTraceCollection, AyayaTraceCollectionServer},
    CollectRequest, ColletionReply, Trace,
};

#[derive(Debug, Default)]
pub struct TraceCollector {}

#[tonic::async_trait]
impl AyayaTraceCollection for TraceCollector {
    async fn collect(
        &self,
        request: tonic::Request<CollectRequest>,
    ) -> std::result::Result<tonic::Response<ColletionReply>, tonic::Status> {
        unimplemented!()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let service = TraceCollector::default();

    Server::builder()
        .add_service(AyayaTraceCollectionServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
