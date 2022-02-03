use std::{
    thread,
    time::{self, Duration},
};

use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use log::info;
use rust_embed::RustEmbed;

extern crate avalanche_ops;
use avalanche_ops::{aws, aws_cloudformation, id};

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
    #[folder = "cloudformation/"]
    #[prefix = "cloudformation/"]
    struct Asset;

    let ec2_vpc_yaml = Asset::get("cloudformation/ec2_vpc.yaml").unwrap();
    let ret = std::str::from_utf8(ec2_vpc_yaml.data.as_ref());
    assert!(ret.is_ok());
    let template_body = ret.unwrap();
    info!("{:?}", template_body);

    let ret = ab!(aws::load_config(None));
    assert!(ret.is_ok());
    let shared_config = ret.unwrap();
    let manager = aws_cloudformation::Manager::new(&shared_config);

    let stack_name = id::generate("test");

    // error should be ignored if it does not exist
    let ret = ab!(manager.delete_stack(&stack_name));
    assert!(ret.is_ok());

    let ret = ab!(manager.create_stack(
        &stack_name,
        Capability::CapabilityNamedIam,
        OnFailure::Delete,
        template_body,
        Some(Vec::from([
            Tag::builder().key("kind").value("avalanche-ops").build(),
            Tag::builder().key("a").value("b").build()
        ])),
        Some(Vec::from([
            Parameter::builder()
                .parameter_key("Id")
                .parameter_value(id::generate("id"))
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
                .parameter_key("SSHIngressIPv4Range")
                .parameter_value("0.0.0.0/0")
                .build(),
        ])),
    ));
    assert!(ret.is_ok());
    let stack = ret.unwrap();
    assert_eq!(stack.name, stack_name);
    assert_eq!(stack.status, StackStatus::CreateInProgress);
    let ret = ab!(manager.poll_stack(
        &stack_name,
        StackStatus::CreateComplete,
        Duration::from_secs(180),
        Duration::from_secs(5),
    ));
    assert!(ret.is_ok());
    let stack = ret.unwrap();
    assert_eq!(stack.name, stack_name);
    assert_eq!(stack.status, StackStatus::CreateComplete);
    let outputs = stack.outputs.unwrap();
    for o in outputs {
        info!("output {:?} {:?}", o.output_key, o.output_value)
    }

    thread::sleep(time::Duration::from_secs(5));

    let ret = ab!(manager.delete_stack(&stack_name));
    assert!(ret.is_ok());
    let ret = ab!(manager.poll_stack(
        &stack_name,
        StackStatus::DeleteComplete,
        Duration::from_secs(120),
        Duration::from_secs(5),
    ));
    assert!(ret.is_ok());
    let stack = ret.unwrap();
    assert_eq!(stack.name, stack_name);
    assert_eq!(stack.status, StackStatus::DeleteComplete);
}
