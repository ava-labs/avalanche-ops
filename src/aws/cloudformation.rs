use std::{
    thread,
    time::{Duration, Instant},
};

use aws_sdk_cloudformation::{
    error::{DeleteStackError, DescribeStacksError},
    model::{Capability, OnFailure, Output, Parameter, StackStatus, Tag},
    types::SdkError,
    Client,
};
use log::{info, warn};

use crate::errors::{
    Error::{Other, API},
    Result,
};

/// Implements AWS CloudFormation manager.
pub struct Manager {
    #[allow(dead_code)]
    shared_config: aws_config::Config,
    cli: Client,
}

impl Manager {
    pub fn new(shared_config: &aws_config::Config) -> Self {
        let cloned = shared_config.clone();
        let cli = Client::new(shared_config);
        Self {
            shared_config: cloned,
            cli,
        }
    }

    /// Creates a CloudFormation stack.
    /// The separate caller is expected to poll the status asynchronously.
    pub async fn create_stack(
        &self,
        stack_name: &str,
        capabilities: Option<Vec<Capability>>,
        on_failure: OnFailure,
        template_body: &str,
        tags: Option<Vec<Tag>>,
        parameters: Option<Vec<Parameter>>,
    ) -> Result<Stack> {
        info!("creating stack '{}'", stack_name);
        let ret = self
            .cli
            .create_stack()
            .stack_name(stack_name)
            .set_capabilities(capabilities)
            .on_failure(on_failure)
            .template_body(template_body)
            .set_tags(tags)
            .set_parameters(parameters)
            .send()
            .await;
        let resp = match ret {
            Ok(v) => v,
            Err(e) => {
                return Err(API {
                    message: format!("failed create_stack {:?}", e),
                    is_retryable: is_error_retryable(&e),
                });
            }
        };

        let stack_id = resp.stack_id().unwrap();
        info!("created stack '{}' with '{}'", stack_name, stack_id);
        Ok(Stack::new(
            stack_name,
            stack_id,
            StackStatus::CreateInProgress,
            None,
        ))
    }

    /// Deletes a CloudFormation stack.
    /// The separate caller is expected to poll the status asynchronously.
    pub async fn delete_stack(&self, stack_name: &str) -> Result<Stack> {
        info!("deleting stack '{}'", stack_name);
        let ret = self.cli.delete_stack().stack_name(stack_name).send().await;
        match ret {
            Ok(_) => {}
            Err(e) => {
                if !is_error_delete_stack_does_not_exist(&e) {
                    return Err(API {
                        message: format!("failed schedule_key_deletion {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
                warn!("stack already deleted ({})", e);
                return Ok(Stack::new(
                    stack_name,
                    "",
                    StackStatus::DeleteComplete,
                    None,
                ));
            }
        };

        Ok(Stack::new(
            stack_name,
            "",
            StackStatus::DeleteInProgress,
            None,
        ))
    }

    /// Polls CloudFormation stack status.
    pub async fn poll_stack(
        &self,
        stack_name: &str,
        desired_status: StackStatus,
        timeout: Duration,
        interval: Duration,
    ) -> Result<Stack> {
        info!(
            "polling stack '{}' with desired status {:?} for timeout {:?} and interval {:?}",
            stack_name, desired_status, timeout, interval,
        );

        let start = Instant::now();
        let mut cnt: u128 = 0;
        loop {
            let elapsed = start.elapsed();
            if elapsed.gt(&timeout) {
                break;
            }

            let itv = {
                if cnt > 0 {
                    // first poll with no wait
                    Duration::from_secs(1)
                } else {
                    interval
                }
            };
            thread::sleep(itv);

            let ret = self
                .cli
                .describe_stacks()
                .stack_name(stack_name)
                .send()
                .await;
            let stacks = match ret {
                Ok(v) => v.stacks,
                Err(e) => {
                    // CFN should fail for non-existing stack, instead of returning 0 stack
                    if is_error_describe_stacks_does_not_exist(&e)
                        && desired_status.eq(&StackStatus::DeleteComplete)
                    {
                        info!("stack already deleted as desired");
                        return Ok(Stack::new(stack_name, "", desired_status, None));
                    }
                    return Err(API {
                        message: format!("failed describe_stacks {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
            };
            let stacks = stacks.unwrap();
            if stacks.len() != 1 {
                // CFN should fail for non-existing stack, instead of returning 0 stack
                return Err(Other {
                    message: String::from("failed to find stack"),
                    is_retryable: false,
                });
            }

            let stack = stacks.get(0).unwrap();
            let current_id = stack.stack_id().unwrap();
            let current_status = stack.stack_status().unwrap();
            info!("poll (current {:?}, elapsed {:?})", current_status, elapsed);

            if desired_status.ne(&StackStatus::DeleteComplete)
                && current_status.eq(&StackStatus::DeleteComplete)
            {
                return Err(Other {
                    message: String::from("stack create/update failed thus deleted"),
                    is_retryable: false,
                });
            }

            if desired_status.eq(&StackStatus::CreateComplete)
                && current_status.eq(&StackStatus::CreateFailed)
            {
                return Err(Other {
                    message: String::from("stack create failed"),
                    is_retryable: false,
                });
            }

            if desired_status.eq(&StackStatus::DeleteComplete)
                && current_status.eq(&StackStatus::DeleteFailed)
            {
                return Err(Other {
                    message: String::from("stack delete failed"),
                    is_retryable: false,
                });
            }

            if current_status.eq(&desired_status) {
                let outputs = stack.outputs();
                let outputs = outputs.unwrap();
                let outputs = Vec::from(outputs);
                let current_stack = Stack::new(
                    stack_name,
                    current_id,
                    current_status.clone(),
                    Some(outputs),
                );
                return Ok(current_stack);
            }

            cnt = cnt + 1;
        }

        return Err(Other {
            message: format!("failed to poll stack {} in time", stack_name),
            is_retryable: true,
        });
    }
}

/// Represents the CloudFormation stack.
#[derive(Debug)]
pub struct Stack {
    pub name: String,
    pub id: String,
    pub status: StackStatus,
    pub outputs: Option<Vec<Output>>,
}

impl Stack {
    pub fn new(name: &str, id: &str, status: StackStatus, outputs: Option<Vec<Output>>) -> Self {
        // ref. https://doc.rust-lang.org/1.0.0/style/ownership/constructors.html
        Self {
            name: String::from(name),
            id: String::from(id),
            status,
            outputs,
        }
    }
}

#[inline]
pub fn is_error_retryable<E>(e: &SdkError<E>) -> bool {
    match e {
        SdkError::TimeoutError(_) | SdkError::ResponseError { .. } => true,
        SdkError::DispatchFailure(e) => e.is_timeout() || e.is_io(),
        _ => false,
    }
}

#[inline]
fn is_error_delete_stack_does_not_exist(e: &SdkError<DeleteStackError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            let msg = format!("{:?}", err);
            msg.contains("does not exist")
        }
        _ => false,
    }
}

#[inline]
fn is_error_describe_stacks_does_not_exist(e: &SdkError<DescribeStacksError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            let msg = format!("{:?}", err);
            msg.contains("does not exist")
        }
        _ => false,
    }
}
