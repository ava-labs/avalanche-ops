
### Example: set up custom network on AWS

Write the configuration file with some default values:

![demo-aws-01](./img/demo-aws-01.png)

![demo-aws-02](./img/demo-aws-02.png)

Then apply the configuration:

![demo-aws-03](./img/demo-aws-03.png)

![demo-aws-04](./img/demo-aws-04.png)

Wait for beacon nodes to be ready:

![demo-aws-05](./img/demo-aws-05.png)

![demo-aws-06](./img/demo-aws-06.png)

Check your S3 bucket for generated artifacts **(all keys are encrypted using KMS)**:

![demo-aws-07](./img/demo-aws-07.png)

Check the beacon nodes:

![demo-aws-08](./img/demo-aws-08.png)

![demo-aws-09](./img/demo-aws-09.png)

![demo-aws-10](./img/demo-aws-10.png)

![demo-aws-11](./img/demo-aws-11.png)

![demo-aws-12](./img/demo-aws-12.png)

Check non-beacon nodes created in a separate Auto Scaling Groups:

![demo-aws-13](./img/demo-aws-13.png)

![demo-aws-14](./img/demo-aws-14.png)

Check how non-beacon nodes discovered other beacon nodes and publish non-beacon nodes information:

![demo-aws-15](./img/demo-aws-15.png)

![demo-aws-16](./img/demo-aws-16.png)

![demo-aws-17](./img/demo-aws-17.png)

![demo-aws-18](./img/demo-aws-18.png)

Check logs from nodes are being published:

![demo-aws-19](./img/demo-aws-19.png)

![demo-aws-20](./img/demo-aws-20.png)

Now that the network is ready, check the metrics and health URL (or access via public IPv4 address):

![demo-aws-21](./img/demo-aws-21.png)

![demo-aws-22](./img/demo-aws-22.png)

![demo-aws-23](./img/demo-aws-23.png)

![demo-aws-24](./img/demo-aws-24.png)

Now the custom network is ready! Check out the genesis file for pre-funded keys:

![demo-aws-25](./img/demo-aws-25.png)

![demo-aws-26](./img/demo-aws-26.png)

To shut down the network, run `avalanche-ops-nodes-aws delete` command:

![demo-aws-27](./img/demo-aws-27.png)

![demo-aws-28](./img/demo-aws-28.png)

