package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/BluBracket/database-risk-scanner/grpc/api"
	"github.com/bserdar/jsonstream"
	"github.com/glebarez/sqlite"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

var (
	// dbType can be postgres, sqlite, mysql or mssql
	// it contains parsed value for the '--dbtype' flag. defaults to postgres.
	dbType dbTypeEnum = dbTypeEnum(dbTypePostgres)
	// uri contains parsed value for the '--uri' flag
	uri string
	// table contains parsed value for '--table' flag
	table string
	// column contains parsed value for '--column' flag
	column string
	// idColumn contains parsed value for '--id-column' flag
	idColumn string
	// output contains parsed value for '--output' flag
	output string
)

var (
	// count of risks found
	riskCount = 0
)

var rootCmd = &cobra.Command{
	Use:   "scan-db",
	Short: "scan-db scans database for risks",
	Long: `scan-db scans database for risks. it scans the given column in the table and
output the risks if any. For example:

./scan-db --uri <uri> --table <table name> --column <column name> --output <path/to/file>

./scan-db --uri postgres://postgres:postgres@localhost:5432/postgres?sslmode=verify-full --table accounts --id-column id --column notes --output out.json
where uri is the standard postgres uri. refer https://pkg.go.dev/github.com/lib/pq for uri format.

./scan-db --dbtype sqlite --uri _testdata/sqlite/accounts.db --table accounts --id-column id --column notes --output out.json
it scans a sqlite DB 'accounts.db' for the given table and column.

./scan-db --dbtype mysql --uri user:password@tcp/mysql --table accounts --id-column id --column notes --output out.json
it scans mysql DB 'mysql' at localhost for given table and column. 
refer https://github.com/go-sql-driver/mysql#dsn-data-source-name for mysql uri format

./scan-db --dbtype=mssql --uri="Server=localhost;Database=sqldb;Trusted_Connection=True;" --table=accounts --id-column=id --column=notes --output=out.json
it scans mssql DB 'sqldb' at localhost using windows authentication for given table and column. 
refer https://github.com/microsoft/go-mssqldb and sqlserver documentation for uri (connection string) format.

`,
	Run: func(cmd *cobra.Command, args []string) {
		err := scanDb()
		if err != nil {
			fmt.Println(err)
		}
	},
}

// scanDb connects to database and scans the column data for risks.
// it starts the blubracket cli as local gRPC server and uses it
// to scan the data for risks.
// on completion, it stops the blubracket cli process.
func scanDb() (err error) {
	// connect to db
	db, err := connectToDb()
	if err != nil {
		return err
	}
	fmt.Println("connected to db.")

	// open output file
	out := os.Stdout
	if output != "" {
		out, err = os.Create(output)
		if err != nil {
			err = errors.Wrap(err, "failed to open output file for write")
			return
		}
		defer out.Close()
	}
	outputStream := jsonstream.NewLineWriter(out)

	// query and send data for scanning.
	rows, err := db.Table(table).Select(idColumn, column).Rows()
	if err != nil {
		err = errors.Wrap(err, "failed to query")
		return
	}
	defer rows.Close()

	// start CLI as server. open a connection to server.
	cmd, conn, err := startCLIServer()
	if err != nil {
		return
	}
	defer cmd.Process.Kill()
	defer conn.Close()
	c := pb.NewBluBracketClient(conn)

	// scan rows
	err = scanRows(rows, c, outputStream)
	if err != nil {
		return
	}

	if riskCount == 0 {
		fmt.Println("no risks found")
	} else {
		fmt.Printf("found %d risk(s)\n", riskCount)
	}
	fmt.Println("scan completed")
	return
}

// scanRows queries the textual data selected per row and send to server to scan for risks.
// it streams each record data to server for scanning and saves the risks found in the output file in json format.
// it tags each risk with the recordId for correlation.
func scanRows(rows *sql.Rows, client pb.BluBracketClient, out jsonstream.LineWriter) (err error) {
	c, err := client.AnalyzeStream(context.Background())
	if err != nil {
		err = errors.Wrap(err, "AnalyzeStream call failed")
		return
	}

	// read response(s) on stream while sending data
	errCh := make(chan error, 1)
	go readRisks(c, out, errCh)

	// read result set. send data to server for scanning.
	fmt.Println("sending records for scanning")
	start := time.Now()
	count := 1
	for rows.Next() {
		var r record
		err = rows.Scan(&r.id, &r.text)
		// fmt.Printf(" data - %v, %v\n", r.id, string(r.text.b))
		if err != nil {
			err = errors.Wrap(err, "failed to read query result")
			return
		}
		fmt.Printf("\rprocessing record : %d", count)
		count++
		if r.text.b == nil {
			// ignore
			continue
		}
		err = sendData(c, r.id, r.text.b)
		if err != nil {
			err = errors.Wrap(err, "failed to send record")
			return
		}
	}
	fmt.Println()
	// close send stream
	err = c.CloseSend()
	if err != nil {
		err = errors.Wrap(err, "failed to close send stream")
		return
	}
	err = rows.Err()
	if err != nil {
		err = errors.Wrap(err, "failed to retrieve query result")
		return
	}
	err = <-errCh
	duration := time.Since(start)
	fmt.Printf("time taken: %v\n", duration)
	return
}

// startCLIServer launches the BluBracket CLI as a local gRPC server process.
// it also establishes a connection to the server.
// it assumes that blubracket binary to be in PATH
func startCLIServer() (cmd *exec.Cmd, conn *grpc.ClientConn, err error) {
	defer func() {
		if err != nil && cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	fmt.Println("Starting BluBracket local gRPC server...")
	const processName = "blubracket"
	serverUri := "unix:" + filepath.Join(os.TempDir(), fmt.Sprintf("blubracket.grpcserver.dbscan-%d", os.Getpid()))
	cmd = exec.Command(processName, "serve", serverUri)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		err = errors.Wrap(err, "failed to start BluBracket CLI process")
		return
	}
	// establish a connection
	conn, err = connectToServer(serverUri)
	return
}

// connectToServer establish a connection to the local gRPC server listening at serverUri.
// it retries a couple of times before failing.
func connectToServer(serverUri string) (conn *grpc.ClientConn, err error) {
	// initial wait
	time.Sleep(4 * time.Second)

	s := 1
	retries := 3
	for {
		// wait for few seconds before dialing
		time.Sleep(time.Duration(s) * time.Second)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)
		conn, err = grpc.DialContext(ctx, serverUri, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		if err == nil {
			return
		}

		retries--
		s *= 2
		if err != nil && retries <= 0 {
			err = errors.Wrap(err, "failed to connect to server")
			return
		} else {
			fmt.Printf("\rretry connect to server after %d seconds. ", s)
		}
	}
}

// sendData sends metadata and data msg on the stream
func sendData(c pb.BluBracket_AnalyzeStreamClient, id interface{}, data []byte) (err error) {
	// send metadata msg
	recordId := fmt.Sprintf("%v", id)
	// fmt.Printf("sending record id - %v", recordId)
	err = c.Send(&pb.AnalyzeStreamRequest{Metadata: &pb.AnalyzeStreamMetadata{Context: recordId}})
	if err != nil {
		err = errors.Wrap(err, "failed to send metadata msg")
		return
	}
	// send data msg
	err = c.Send(&pb.AnalyzeStreamRequest{Data: data})
	if err != nil {
		err = errors.Wrap(err, "failed to send data msg")
		return
	}
	return
}

// readRisks receive response(s) containing risk found. it adds recordId to the risk for correlation and
// writes it to the output file in json.
func readRisks(c pb.BluBracket_AnalyzeStreamClient, out jsonstream.LineWriter, errCh chan error) {
	var err error
	defer func() {
		errCh <- err
		close(errCh)
	}()

	for {
		var asResponse *pb.AnalyzeStreamResponse
		asResponse, err = c.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			err = errors.Wrap(err, "failed receiving data from server")
			return
		}
		// fmt.Printf("response context: %v\n", asResponse.Context)
		err = writeRisk(asResponse.Metadata.Context, asResponse.Risk, out)
		if err != nil {
			return
		}
		riskCount++
	}
}

// writeRisk writes risk in json format to the output including recordId
func writeRisk(recordId string, risk *pb.Risk, out jsonstream.LineWriter) (err error) {
	r := map[string]interface{}{
		"Table":          table,
		"Column":         column,
		"RecordId":       recordId,
		"Category":       risk.Category,
		"Type":           risk.Type,
		"Severity":       risk.Severity,
		"Value":          risk.Value,
		"TextualContext": risk.TextualContext,
		"Line1":          risk.Line1,
		"Col1":           risk.Col1,
		"Line2":          risk.Line2,
		"Col2":           risk.Col2,
		"Tags":           risk.Tags,
	}
	err = out.Marshal(r)
	if err != nil {
		err = errors.Wrap(err, "failed writing risk to output")
		return
	}
	return
}

// connectToDb connects to postgres database.
// for connecting to other gorm supported databases, refer https://gorm.io/docs/connecting_to_the_database.html
func connectToDb() (db *gorm.DB, err error) {
	db, err = gorm.Open(getDialector(), &gorm.Config{})
	if err != nil {
		err = errors.Wrap(err, "failed to connect to database")
		return
	}

	return
}

func getDialector() (d gorm.Dialector) {
	switch dbType {
	case dbTypeEnum(dbTypePostgres):
		d = postgres.Open(uri)
	case dbTypeEnum(dbTypeSqlite):
		d = sqlite.Open(uri)
	case dbTypeEnum(dbTypeMysql):
		d = mysql.Open(uri)
	case dbTypeEnum(dbTypeMssql):
		d = sqlserver.Open(uri)
	default:
		// should not get here
		panic(fmt.Sprintf("unknown dbtype : %v", dbType))
	}
	return
}

// record stores values for 'idColumn' and 'column' to be scanned for a row
type record struct {
	id   interface{}
	text textType
}

// textType implements the Scanner interface required for custom type
// refer https://pkg.go.dev/database/sql#Scanner
type textType struct {
	b []byte
}

func (t *textType) Scan(rawData interface{}) (err error) {
	//fmt.Printf("rawData type: %T\n", rawData)
	if rawData == nil {
		t.b = nil
		return
	}
	if s, ok := rawData.(string); ok {
		t.b = []byte(s)
		return
	}
	if b, ok := rawData.([]byte); ok {
		//fmt.Printf("data : %s\n", string(b))
		t.b = b
		return
	}
	err = errors.New(fmt.Sprintf("unexpected data type: %T", rawData))
	return
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// dbTypeEnum is custom value type and implements pFlag.Value interface
type dbTypeEnum string

const (
	dbTypePostgres string = "postgres"
	dbTypeSqlite   string = "sqlite"
	dbTypeMysql    string = "mysql"
	dbTypeMssql    string = "mssql"
)

var supportedDatabases = []string{dbTypePostgres, dbTypeSqlite, dbTypeMysql, dbTypeMssql}
var supportedDatabasesText = strings.Join(supportedDatabases, ", ")

func (t *dbTypeEnum) String() string {
	return string(*t)
}

func (t *dbTypeEnum) Type() string {
	return "dbTypeEnum"
}

func (t *dbTypeEnum) Set(v string) error {
	switch v {
	case dbTypePostgres, dbTypeSqlite, dbTypeMysql, dbTypeMssql:
		*t = dbTypeEnum(v)
		return nil
	default:
		return errors.New(fmt.Sprintf("Unsupported dbtype : %s. Supported dbtypes are (%s)",
			v, supportedDatabasesText))
	}
}

func init() {
	rootCmd.Flags().VarP(&dbType, "dbtype", "d", fmt.Sprintf("Specify database (%s).", supportedDatabasesText))
	rootCmd.Flags().StringVarP(&uri, "uri", "u", "", "Specify database uri")
	rootCmd.Flags().StringVarP(&table, "table", "t", "", "Specify table name")
	rootCmd.Flags().StringVarP(&column, "column", "c", "", "Specify column name to scan")
	rootCmd.Flags().StringVarP(&idColumn, "id-column", "i", "", "Specify record-id column name for reference in result")
	rootCmd.Flags().StringVarP(&output, "output", "o", "", "Specify output file to store results. Else stdout.")
	rootCmd.MarkFlagRequired("uri")
	rootCmd.MarkFlagRequired("table")
	rootCmd.MarkFlagRequired("column")
	rootCmd.MarkFlagRequired("id-column")
}
