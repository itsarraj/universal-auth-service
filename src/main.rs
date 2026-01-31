use uas::run;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await
}
