# API Script

- Will test all API functions and pipe the output to their respective files.
- So far everything is correctly tested except for API functions that incorporate channels.

## Usage

- Follow https://github.com/filecoin-project/lotus/blob/7d166fd730da8d771b86c37314c162e2a9829eef/documentation/en/local-dev-net.md to setup a local devnet.
- Run the following commands to setup the required Filecoin components after setup:
    - `lotus daemon --lotus-make-genesis=dev.gen --genesis-template=localnet.json --bootstrap=false`
    - `lotus-storage-miner run --nosync`
    - `lotus-seal-worker run --address 127.0.0.1:3456`
- You may be required to run the following command as well:
    - `STORAGE_API_INFO="JWT_TOKEN:/ip4/127.0.0.1/tcp/2345/http"`
- Program assumes that the lotus repo in scope is located at `~/lotus-review`.
- Can be run simply by executing `python test-api.py`.