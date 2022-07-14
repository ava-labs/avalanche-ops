use std::{fs::File, io::Read, sync::Arc, thread, time};

use aws_manager::{
    self,
    kms::{self, envelope},
    s3,
};
use infra_aws::certs;

/// cargo run --example certs
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    macro_rules! ab {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    log::info!("creating AWS resources!");
    let shared_config = ab!(aws_manager::load_config(None)).unwrap();

    let kms_manager = kms::Manager::new(&shared_config);
    let cmk = ab!(kms_manager.create_key("test key description")).unwrap();
    let envelope_manager = envelope::Manager::new(
        kms_manager.clone(),
        cmk.id.clone(),
        "test-aad-tag".to_string(),
    );

    let s3_manager = s3::Manager::new(&shared_config);
    let s3_bucket = format!(
        "infra-aws-examples-tests-certs-{}",
        random_manager::string(10).to_lowercase()
    );
    ab!(s3_manager.create_bucket(&s3_bucket)).unwrap();

    let certs_manager = certs::Manager {
        envelope_manager,
        s3_manager: s3_manager.clone(),
        s3_bucket: s3_bucket.clone(),
        s3_key_tls_key: String::from("staking.key"),
        s3_key_tls_cert: String::from("staking.crt"),
    };

    let tls_key_path1 = random_manager::tmp_path(10, None).unwrap();
    let tls_cert_path1 = random_manager::tmp_path(10, None).unwrap();

    let (node_id1, generated1) =
        ab!(certs_manager.load_or_generate(&tls_key_path1, &tls_cert_path1)).unwrap();
    let (node_id2, generated2) =
        ab!(certs_manager.load_or_generate(&tls_key_path1, &tls_cert_path1)).unwrap();
    assert!(generated1);
    assert!(!generated2);

    let tls_key_path2 = random_manager::tmp_path(10, None).unwrap();
    let tls_cert_path2 = random_manager::tmp_path(10, None).unwrap();
    let node_id3 = ab!(certs_manager.download(&tls_key_path2, &tls_cert_path2)).unwrap();

    assert_eq!(node_id1, node_id2);
    assert_eq!(node_id2, node_id3);
    log::info!("generated node Id {}", node_id1);

    thread::sleep(time::Duration::from_secs(3));

    ab!(s3_manager.delete_objects(Arc::new(s3_bucket.clone()), None)).unwrap();
    thread::sleep(time::Duration::from_secs(3));
    ab!(s3_manager.delete_bucket(&s3_bucket)).unwrap();
    ab!(kms_manager.schedule_to_delete(&cmk.id)).unwrap();

    let mut src_file = File::open(tls_key_path1).unwrap();
    let mut src_file_contents = Vec::new();
    src_file.read_to_end(&mut src_file_contents).unwrap();
    let mut dst_file = File::open(tls_key_path2).unwrap();
    let mut dst_file_contents = Vec::new();
    dst_file.read_to_end(&mut dst_file_contents).unwrap();
    assert!(cmp_manager::eq_vectors(
        &src_file_contents,
        &dst_file_contents
    ));

    let mut src_file = File::open(tls_cert_path1).unwrap();
    let mut src_file_contents = Vec::new();
    src_file.read_to_end(&mut src_file_contents).unwrap();
    let mut dst_file = File::open(tls_cert_path2).unwrap();
    let mut dst_file_contents = Vec::new();
    dst_file.read_to_end(&mut dst_file_contents).unwrap();
    assert!(cmp_manager::eq_vectors(
        &src_file_contents,
        &dst_file_contents
    ));
}
