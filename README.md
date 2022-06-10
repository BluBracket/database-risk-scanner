# Database Risk Scanner

This tool demonstrates to analyze textual data stored in a postgres database using BluBracket CLI as local gRPC server. 

This fully-functional solution uses the BluBracket CLI to do the risk detection heavy lifting,
combined with open-source `scan-db` client code written in golang.

This tool runs entirely locally. Installation is almost as easy as cloning the repo,
and you should have a working POC in minutes.

## Installation

1. Install the BluBracket CLI (see below)
2. Clone or download this repo

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

This will build the `scan-db` client.

```
cd ./scan-db
go build
```

## Usage
Open command/terminal window. 


```
# Scan a given column in the table 
./scan-db --uri <database-uri> --table <table name>  --column <column to scan> --id-column <record id column> --output out.json

# scan `info` column of `orders` table in postgres database installed locally with sslmode disabled running on default port `5432`
# uri is the standard postgres connection string. refer https://pkg.go.dev/github.com/lib/pq
./scan-db --uri postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable --table orders --id-column id --column info --output out.json

```


## Modifying and contributing

This Apache-licensed project is open for re-use and improvements by all.
Please open an issue or pull request if you find any bugs or see an opportunity for improvement.

Hit us up on Twitter at [@BluBracket](https://twitter.com/blubracket) to tell us how you're using it!
