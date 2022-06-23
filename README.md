# Database Risk Scanner

This tool demonstrates to analyze textual data stored in a postgres database using BluBracket CLI. 

This fully-functional solution uses the BluBracket CLI to do the risk detection heavy lifting.

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
# uri is the standard connection string for the database. 
./scan-db --dbtype <database> --uri <database-uri> --table <table name>  --column <column to scan> --id-column <record id column> --output out.json

# sample test steps (for postgres):
# 1. create test table `accounts` using `/scan-db/_testdata/postgres/accounts.sql` in local postgres db for development.
#    assumptions - username - `postgres`, password - `postgres`, port - `5432`, sslmode enabled
#    database-uri  - postgres://postgres:postgres@localhost:5432/postgres?sslmode=verify-full 
#    for details of postgres database uri - refer https://pkg.go.dev/github.com/lib/pq e.g. sslmode field other values
# 2. scan `notes` column of `accounts` table. accounts table has `id column` as `id`
./scan-db --dbtype postgres --uri postgres://postgres:postgres@localhost:5432/postgres?sslmode=verify-full --table accounts --id-column id --column notes --output out.json
# 3. `out.json` will have one password risk captured.
# 4. scan `info` column of `accounts` table. 
./scan-db --dbtype postgres --uri postgres://postgres:postgres@localhost:5432/postgres?sslmode=verify-full --table accounts --id-column id --column info
# 5. scan will not find any risks as there are no secrets stored in this column.

Steps can be modified to try it with --dbtype sqlite, mysql or mssql. _testdata has sample data for each type of database.

For help:
./scan-db --help
```


## Modifying and contributing

This Apache-licensed project is open for re-use and improvements by all.
Please open an issue or pull request if you find any bugs or see an opportunity for improvement.

Hit us up on Twitter at [@BluBracket](https://twitter.com/blubracket) to tell us how you're using it!
