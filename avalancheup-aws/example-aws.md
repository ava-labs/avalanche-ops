
## Example: set up custom network on AWS

*See ["Custom network with NO initial database state, with subnet-evm"](recipes-aws.md#custom-network-with-no-initial-database-state-with-subnet-evm) for the full commands.*

Write the configuration file with some default values:

![example-aws/01](./img/example-aws/01.png)

![example-aws/02](./img/example-aws/02.png)

<hr>

Then apply the configuration:

![example-aws/03](./img/example-aws/03.png)

![example-aws/04](./img/example-aws/04.png)

<hr>

Wait for anchor nodes to be ready:

![example-aws/05](./img/example-aws/05.png)

![example-aws/06](./img/example-aws/06.png)

<hr>

Check your S3 bucket for generated artifacts **(all private keys are encrypted using KMS/envelope encryption)**:

![example-aws/07](./img/example-aws/07.png)

<hr>

Check the anchor nodes:

![example-aws/08](./img/example-aws/08.png)

![example-aws/09](./img/example-aws/09.png)

![example-aws/10](./img/example-aws/10.png)

![example-aws/11](./img/example-aws/11.png)

![example-aws/12](./img/example-aws/12.png)

<hr>

Check non-anchor nodes created in a separate Auto Scaling Groups:

![example-aws/13](./img/example-aws/13.png)

![example-aws/14](./img/example-aws/14.png)

<hr>

Check how non-anchor nodes discovered other anchor nodes and publish non-anchor nodes information:

![example-aws/15](./img/example-aws/15.png)

![example-aws/16](./img/example-aws/16.png)

![example-aws/17](./img/example-aws/17.png)

![example-aws/18](./img/example-aws/18.png)

<hr>

Check logs and metrics from nodes are being published:

![example-aws/19](./img/example-aws/19.png)

![example-aws/20](./img/example-aws/20.png)

<hr>

Now that the network is ready, check the metrics and health URL (or access via public IPv4 address):

![example-aws/21](./img/example-aws/21.png)

![example-aws/22](./img/example-aws/22.png)

![example-aws/23](./img/example-aws/23.png)

![example-aws/24](./img/example-aws/24.png)

<hr>

Now the custom network is ready! Check out the genesis file:

![example-aws/25](./img/example-aws/25.png)

![example-aws/26](./img/example-aws/26.png)

<hr>

To interact with C-chain via MetaMask, add the DNS RPC endpoint as a custom network as follows:

![example-aws/27](./img/example-aws/27.png)

![example-aws/28](./img/example-aws/28.png)

![example-aws/29](./img/example-aws/29.png)

Or use [Core wallet](https://chrome.google.com/webstore/detail/core/agoakfejjabomempkjlepdflaleeobhb):

![example-aws/core-1](./img/example-aws/core-1.png)

![example-aws/core-2](./img/example-aws/core-2.png)

![example-aws/core-3](./img/example-aws/core-3.png)

<hr>

Import the test keys for pre-funded wallets:

![example-aws/30](./img/example-aws/30.png)

![example-aws/31](./img/example-aws/31.png)

![example-aws/32](./img/example-aws/32.png)

![example-aws/33](./img/example-aws/33.png)

<hr>

### Optional: install `subnet-evm` in the custom network

To set up [`subnet-evm`](https://github.com/ava-labs/subnet-evm), use [`subnet-cli`](https://github.com/ava-labs/subnet-cli) to add two non-anchor nodes as validators:

![example-aws/34](./img/example-aws/34.png)

![example-aws/35](./img/example-aws/35.png)

To create a custom blockchain for `subnet-evm`:

![example-aws/36](./img/example-aws/36.png)

![example-aws/37](./img/example-aws/37.png)

Restart the nodes with the tracked subnet ID as instructed **(this will be automated in future `avalanche-ops` releases)**:

![example-aws/38](./img/example-aws/38.png)

![example-aws/39](./img/example-aws/39.png)

![example-aws/40](./img/example-aws/40.png)

![example-aws/41](./img/example-aws/41.png)

To add `subnet-evm` network to MetaMask, use the newly created blockchain ID for RPC endpoints:

![example-aws/42](./img/example-aws/42.png)

Note that the existing test keys are pre-funded (as in C-chain):

![example-aws/43](./img/example-aws/43.png)

To look at the `subnet-vm` logs:

![example-aws/44](./img/example-aws/44.png)

![example-aws/45](./img/example-aws/45.png)

<hr>

To shut down the network, run `avalancheup-aws delete` command:

![example-aws/46](./img/example-aws/46.png)

![example-aws/47](./img/example-aws/47.png)

![example-aws/48](./img/example-aws/48.png)

<hr>
