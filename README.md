# Database Risk Scanner

This tool demonstrates to analyze stream of data using BluBracket CLI as local gRPC server. 
For example: Stream text data stored in database column with a database query 
using your favorite db query tool or custom script and scan it for any security risks.

This fully-functional solution uses the BluBracket CLI to do the risk detection heavy lifting,
combined with open-source `stream-scanner` client code written in golang to interact with CLI
and a python script to query the database.

This tool runs entirely locally. Installation is almost as easy as cloning the repo,
and you should have a working POC in minutes.

## Installation

1. Install the BluBracket CLI (see below)
2. Clone or download this repo
2. `pipenv sync` inside the repo to install Python dependencies

Requires Python3 and pip, but [you probably already have those](https://pip.pypa.io/en/stable/installation/).
Requires [golang installation](https://go.dev/doc/install)

### Install the BluBracket CLI

The BluBracket CLI is a high-performance, compact risk scanner written in Go.
Unlike some tools, it runs entirely locally without sending any data to remote hosts
(unless explicitly configured otherwise).

macOS, multiple Linux distros, and Windows are all supported.

Use these direct links to download the executables:

- macOS: https://static.blubracket.com/cli/latest/blubracket-macos
- Linux: https://static.blubracket.com/cli/latest/blubracket-linux
- Windows: https://static.blubracket.com/cli/latest/blubracket-win.exe

For example, to download and run the latest BluBracket CLI on macOS, you could run:

```
curl https://static.blubracket.com/cli/latest/blubracket-macos -o blubracket
chmod +x ./blubracket
mv ./blubracket /usr/local/bin/
```

## Build

This will build the `stream-scanner` client.

```
cd ./grpc/stream-scanner
go build
```

## Usage

Open one command/terminal window. Start blubracket CLI server.

```
blubracket serve unix:/tmp/blubracket-cli-server
```

Open another command/terminal window. Using stream-scanner client, stream data to be scanned 
to the cli server. Risks encountered are displayed on the console.

For example, stream the database query result using a python script to stream-scanner.
 

```
pipenv run python database_scan.py --database sampledb --query query.sql | stream-scanner unix:/blubracket-cli-server
```


## Modifying and contributing

This Apache-licensed project is open for re-use and improvements by all.
Please open an issue or pull request if you find any bugs or see an opportunity for improvement.

Hit us up on Twitter at [@BluBracket](https://twitter.com/blubracket) to tell us how you're using it!
