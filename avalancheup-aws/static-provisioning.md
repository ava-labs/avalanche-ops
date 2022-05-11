

# Statis provisioning on AWS

Each bootstrapping `avalanched` must create the following resources only once, in the residing zone and per node count: (1) EBS volume, and (2) TLS certificate.

The static EBS volume can ensure data persistency in case of hardware failures. The static TLS certificate enables the static node ID. The idea is to create them only once for each node, and whenever its instance gets terminated, release the resources so they can reused for the new instance.

In order to maintain the invariant that each node is one-to-one mapped to the set of resources, we persist the mapping in the external storage S3: S3 reads are consistent thus safe to use as a metadata storage.

In addition, we can safely assume EC2 describe API always returns the correct state: If an EC2 instance gets terminated, the attached EBS volume state becomes "detached".

## AWS resource locality

EBS volume is zone-specific thus not to be reused in other zones: When a node becomes unhealthy (e.g., availability zone outages), ASG will launch a new instance but won't be able to reuse the EBS volume if launched in a different availability zone.

Meanwhile the staking TLS certificates can be uploaded to S3 for cross-zonal access, and indeed the most important invariant to protect a node against crash faults.

## AWS resource mapping

For efficient querying, each resource will be tagged with the corresponding subnet ID. We can safely assume that the AWS tag storage is consistent and tag-filter query volume will be reasonably small, as only required for the initial bootstrapping phase.

The data in the EBS volume are interchangeable across different node entities, and the volumes may remain unused if there is no remaining EC2 instance in the zone, but not to be deleted unless the user deletes the whole cluster. The worst thing that can happen is wasted resources and AWS bills: A user creates the cluster with the size `X` and permanently scales down to `Y` -- then the `X - Y` number of EBS volumes remain unused. In the future, we can either support resource clean-up tools for orphaned EBS volumes, and leave this up to the user for now.

Meanwhile the staking TLS certificates (once created) must be used at all times, so long as the ASG desired capacity remains the same (or increases): In case of EC2 instance replacement, the TLS certificates must be reused by the upcoming new EC2 instance. Which means each `avalanched` must ensure the uniqueness of the TLS certificates and track its availability in real time: If a staking certificate is being (or about to be) used by a bootstrapping node, it should not be reused in other nodes.

The available EBS volumes can be identified with its volume attachment status, the subnet ID, and its cluster name tag value. The staking TLS certificates can be identified with the corresponding node ID, the hash digest of certificate. The availability of each certificate can be tracked in S3, the simplest and strongly consistent metadata storage. The keys will be updated as follows:

```
# TODO: s3 bucket, key hierarchy
```

## FAQ: What about ENI? What about IPv6?

Reserving a static ENI with a dedicated IP for each node will be helpful for peer status monitoring. However, similar to EBS, the ENI is a zonal resource which cannot be reused if a new EC2 instance is launched in a different availability zone. The same applies to IPv6 as it is bound to a specific subnet range. This adds operational complexity and resource overheads in addition to the EBS volumes. We can revisit when AWS supports elastic IPs in IPv6.

## FAQ: What about EIP?

Elastic IP (IPv4) can be used to reserve a static IP for each node. And indeed this is the most viable option on AWS. However, we are looking to scale the Avalanche network to millions of machines. Thus we want to avoid the use of limited IPv4 address space if possible. This also adds operational complexity and incurs extra AWS bills. Given that changing node IPs does not have any impact on the new upcoming Avalanche nodes, we choose not to enforce static IPs on the nodes.

## FAQ: What about Kubernetes? What about CSI EBS plugin?

Indeed, Kubernetes/EKS with CSI plugin can do all of this. However, the goal of this project is to operate a node in most affordable way. We want to achieve the same with more efficiency (and less spending).
