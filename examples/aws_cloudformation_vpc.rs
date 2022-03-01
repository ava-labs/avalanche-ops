use std::{
    thread,
    time::{self, Duration},
};

use aws_sdk_cloudformation::model::{OnFailure, Parameter, StackStatus, Tag};
use log::info;
use rust_embed::RustEmbed;

extern crate avalanche_ops;
use avalanche_ops::{
    aws::{self, cloudformation},
    utils::random,
};

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

    info!("creating AWS CloudFormation resources!");

    #[derive(RustEmbed)]
    #[folder = "cloudformation/avalanche-node/"]
    #[prefix = "cloudformation/avalanche-node/"]
    struct Asset;

    let vpc_yaml = Asset::get("cloudformation/avalanche-node/vpc.yaml").unwrap();
    let ret = std::str::from_utf8(vpc_yaml.data.as_ref());
    let template_body = ret.unwrap();
    info!("{:?}", template_body);

    let ret = ab!(aws::load_config(None));
    let shared_config = ret.unwrap();
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);

    let stack_name = random::generate_id("test");

    // error should be ignored if it does not exist
    let ret = ab!(cloudformation_manager.delete_stack(&stack_name));
    assert!(ret.is_ok());

    let ret = ab!(cloudformation_manager.create_stack(
        &stack_name,
        None,
        OnFailure::Delete,
        template_body,
        Some(Vec::from([
            Tag::builder().key("KIND").value("avalanche-ops").build(),
            Tag::builder().key("a").value("b").build()
        ])),
        Some(Vec::from([
            Parameter::builder()
                .parameter_key("Id")
                .parameter_value(random::generate_id("id"))
                .build(),
            Parameter::builder()
                .parameter_key("VpcCidr")
                .parameter_value("10.0.0.0/16")
                .build(),
            Parameter::builder()
                .parameter_key("PublicSubnetCidr1")
                .parameter_value("10.0.64.0/19")
                .build(),
            Parameter::builder()
                .parameter_key("PublicSubnetCidr2")
                .parameter_value("10.0.128.0/19")
                .build(),
            Parameter::builder()
                .parameter_key("PublicSubnetCidr3")
                .parameter_value("10.0.192.0/19")
                .build(),
            Parameter::builder()
                .parameter_key("IngressIpv4Range")
                .parameter_value("0.0.0.0/0")
                .build(),
            Parameter::builder()
                .parameter_key("HttpPort")
                .parameter_value("9650")
                .build(),
            Parameter::builder()
                .parameter_key("StakingPort")
                .parameter_value("9651")
                .build(),
        ])),
    ));
    let stack = ret.unwrap();
    assert_eq!(stack.name, stack_name);
    assert_eq!(stack.status, StackStatus::CreateInProgress);
    let ret = ab!(cloudformation_manager.poll_stack(
        &stack_name,
        StackStatus::CreateComplete,
        Duration::from_secs(500),
        Duration::from_secs(30),
    ));
    let stack = ret.unwrap();
    assert_eq!(stack.name, stack_name);
    assert_eq!(stack.status, StackStatus::CreateComplete);
    let outputs = stack.outputs.unwrap();
    for o in outputs {
        info!("output {:?} {:?}", o.output_key, o.output_value)
    }

    thread::sleep(time::Duration::from_secs(5));

    let ret = ab!(cloudformation_manager.delete_stack(&stack_name));
    assert!(ret.is_ok());
    let ret = ab!(cloudformation_manager.poll_stack(
        &stack_name,
        StackStatus::DeleteComplete,
        Duration::from_secs(500),
        Duration::from_secs(30),
    ));
    let stack = ret.unwrap();
    assert_eq!(stack.name, stack_name);
    assert_eq!(stack.status, StackStatus::DeleteComplete);
}
