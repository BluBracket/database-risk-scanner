package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"

	pb "github.com/BluBracket/database-risk-scanner/grpc/api"
	"github.com/bserdar/jsonstream"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
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

var rootCmd = &cobra.Command{
	Use:   "scan-db",
	Short: "scan-db scans database for risks",
	Long: `scan-db scans postgres database for risks. it scans the given column in the table and
output the risks if any. For example:

scan-db --database <uri> --table <table name> --column <column name> --output <path/to/file>`,
	Run: func(cmd *cobra.Command, args []string) {
		err := scanDb()
		if err != nil {
			fmt.Println(err)
		}
	},
}

func scanDb() (err error) {
	// connect to db
	db, err := connectToDb()
	if err != nil {
		return err
	}
	defer db.Close()
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
	err = queryDb(db, outputStream)
	if err != nil {
		return err
	}
	return
}

func connectToDb() (db *sql.DB, err error) {
	db, err = sql.Open("pgx", uri)
	if err != nil {
		err = errors.Wrap(err, "failed to connect")
		return
	}

	err = db.Ping()
	if err != nil {
		err = errors.Wrap(err, "failed to ping")
		return
	}
	return
}

// queryDb queries the given column in the given table and scans it for risks.
// it starts blubracket cli as gRPC server. it streams each record data to server
// for scanning and saves the risks found in the output file in json format.
// it tags each risk with the recordId for correlation. on completion, it stops
// the blubracket cli process.
func queryDb(db *sql.DB, out jsonstream.LineWriter) (err error) {
	rows, err := db.Query(fmt.Sprintf("select %s, %s from %s limit 10", idColumn, column, table))
	if err != nil {
		err = errors.Wrap(err, "failed to query")
		return
	}
	defer rows.Close()
	types, err := rows.ColumnTypes()
	if err != nil {
		err = errors.Wrap(err, "failed to get column types from query result")
		return
	}
	databaseTypeName := types[1].DatabaseTypeName()
	if !isSupportedType(databaseTypeName) {
		err = fmt.Errorf("column type not supported: %s", databaseTypeName)
		return
	}

	// start server. open a connection to server.
	cmd, conn, err := startServer()
	if err != nil {
		return
	}
	defer cmd.Process.Kill()
	defer conn.Close()
	c := pb.NewBluBracketClient(conn)

	// read result set. send data to server for scanning.
	fmt.Println("sending records for scanning")
	for rows.Next() {
		var id, data any
		err = rows.Scan(&id, &data)
		if err != nil {
			err = errors.Wrap(err, "failed to read query result")
			return
		}
		err = scanData(c, id, parseData(databaseTypeName, data), out)
		if err != nil {
			err = errors.Wrap(err, "failed to scan record")
			return
		}
		fmt.Print(".")
	}
	err = rows.Err()
	if err != nil {
		err = errors.Wrap(err, "failed to retrieve query result")
		return
	}
	fmt.Println("scan completed")
	return
}

// startServer launches the blubracket cli as a local gRPC server process.
// it also establishes a connection to the server.
// it assumes that blubracket binary to be in PATH
func startServer() (cmd *exec.Cmd, conn *grpc.ClientConn, err error) {
	defer func() {
		if err != nil && cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	fmt.Println("Starting blubracket local gRPC server...")
	const processName = "blubracket"
	serverUri := "unix:" + filepath.Join(os.TempDir(), fmt.Sprintf("blubracket.grpcserver.dbscan-%d", os.Getpid()))
	cmd = exec.Command(processName, "serve", serverUri)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		err = errors.Wrap(err, "failed to start blubracket cli process")
		return
	}
	// given some time for server to listen
	time.Sleep(time.Second)
	// establish a connection
	conn, err = grpc.Dial(serverUri, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		err = errors.Wrap(err, "failed to connect to server")
		return
	}
	return
}

// scanData invokes AnalyzeStream method on the gRPC server to scan the given data and write risks
// to output if any. it sends metadata and data msg on the stream. it closes the send stream after
// sending the data. it reads responses containing risks if any.
func scanData(client pb.BluBracketClient, id any, data []byte, out jsonstream.LineWriter) (err error) {
	// open streaming session
	recordId := fmt.Sprintf("%v", id)
	c, err := client.AnalyzeStream(context.Background())
	if err != nil {
		err = errors.Wrap(err, "AnalyzeStream call failed")
		return
	}
	// send metadata msg
	err = c.Send(&pb.AnalyzeStreamRequest{Metadata: &pb.AnalyzeStreamMetadata{StreamName: recordId}})
	if err != nil {
		err = errors.Wrap(err, "failed to send metadata msg")
		return
	}

	// read response(s) on stream while sending data
	done := make(chan bool)
	go readRisks(c, recordId, out, done)

	// send data msg
	err = c.Send(&pb.AnalyzeStreamRequest{Data: data})
	if err != nil {
		err = errors.Wrap(err, "failed to send data msg")
		return
	}
	// close send stream
	err = c.CloseSend()
	if err != nil {
		err = errors.Wrap(err, "failed to close send stream")
		return
	}

	<-done
	return
}

// readRisks receive response(s) containing risk found. it add recordId to the risk for correlation and
// writes it to the output file in json.
func readRisks(c pb.BluBracket_AnalyzeStreamClient, recordId string, out jsonstream.LineWriter, done chan bool) {
	defer close(done)
	for {
		asResponse, err := c.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("failed receiving data from server: %v\n", err)
			return
		}
		err = writeRisk(recordId, asResponse.Risk, out)
		if err != nil {
			fmt.Printf("failed writing risk to output: %v\n", err)
			return
		}
	}
}

// writeRisk writes risk in json format to the output including recordId
func writeRisk(recordId string, risk *pb.Risk, out jsonstream.LineWriter) error {
	r := map[string]interface{}{
		"RecordId": recordId,
		"Category": risk.Category,
		"Type":     risk.Type,
		"Line1":    risk.Line1,
		"Col1":     risk.Col1,
		"Line2":    risk.Line2,
		"Col2":     risk.Col2,
		"Tags":     risk.Tags,
	}
	return out.Marshal(r)
}

// isSupportedType checks the columnType to be a text type
func isSupportedType(dt string) bool {
	supportedTypes := map[string]interface{}{
		"VARCHAR":  nil,
		"NVARCHAR": nil,
		"TEXT":     nil,
		"_TEXT":    nil,
		"BPCHAR":   nil,
		"JSON":     nil,
	}
	_, ok := supportedTypes[dt]
	return ok
}

// TODO: need to test
func parseData(databaseTypeName string, rawData any) (data []byte) {
	// fmt.Printf("database TypeName: %s, rawData type: %T\n", databaseTypeName, rawData)
	if s, ok := rawData.(string); ok {
		return []byte(s)
	}
	if b, ok := rawData.([]byte); ok {
		// fmt.Printf("data : %s\n", string(b))
		return b
	}
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

func init() {
	rootCmd.Flags().StringVarP(&uri, "uri", "u", "", "Specify postgres database uri")
	rootCmd.Flags().StringVarP(&table, "table", "t", "", "Specify table name")
	rootCmd.Flags().StringVarP(&column, "column", "c", "", "Specify column name to scan")
	rootCmd.Flags().StringVarP(&idColumn, "id-column", "i", "", "Specify record-id column name for reference in result")
	rootCmd.Flags().StringVarP(&output, "output", "o", "", "Specify output file to store results. Else stdout.")
	rootCmd.MarkFlagRequired("uri")
	rootCmd.MarkFlagRequired("table")
	rootCmd.MarkFlagRequired("column")
	rootCmd.MarkFlagRequired("id-column")
}
