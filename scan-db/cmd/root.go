package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	pb "github.com/BluBracket/database-risk-scanner/grpc/api"
	"github.com/bserdar/jsonstream"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

var (
	// count of risks found
	riskCount = 0
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

	if riskCount == 0 {
		fmt.Println("no risks found")
	} else {
		fmt.Printf("found %d risk(s)\n", riskCount)
	}
	return
}

// connectToDb connects to postgres database.
// for connecting to other gorm supported databases, refer https://gorm.io/docs/connecting_to_the_database.html
func connectToDb() (db *gorm.DB, err error) {
	db, err = gorm.Open(postgres.Open(uri), &gorm.Config{})
	if err != nil {
		err = errors.Wrap(err, "failed to connect to database")
		return
	}

	return
}

// queryDb queries the given column in the given table and scans it for risks.
// it starts blubracket cli as gRPC server. it streams each record data to server
// for scanning and saves the risks found in the output file in json format.
// it tags each risk with the recordId for correlation. on completion, it stops
// the blubracket cli process.
func queryDb(db *gorm.DB, out jsonstream.LineWriter) (err error) {
	rows, err := db.Table(table).Select(idColumn, column).Rows()
	if err != nil {
		err = errors.Wrap(err, "failed to query")
		return
	}
	defer rows.Close()

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
	count := 1
	for rows.Next() {
		var r record
		err = rows.Scan(&r.id, &r.text)
		//fmt.Printf("%v, %v\n", r.id, string(r.text.b))
		if err != nil {
			err = errors.Wrap(err, "failed to read query result")
			return
		}
		err = scanData(c, r.id, r.text.b, out)
		if err != nil {
			err = errors.Wrap(err, "failed to scan record")
			return
		}
		fmt.Printf("\rprocessing record : %d", count)
		count++
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
	// establish a connection
	conn, err = connectToServer(serverUri)
	return
}

// connectToServer establish a connection to the local gRPC server listening at serverUri.
// it retries a couple of times before failing.
func connectToServer(serverUri string) (conn *grpc.ClientConn, err error) {
	s := 1
	retries := 3
	for {
		// wait for few seconds before dialing
		time.Sleep(time.Duration(s) * time.Second)
		conn, err = grpc.Dial(serverUri, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err == nil {
			return
		}

		retries--
		s *= 2
		if err != nil && retries <= 0 {
			err = errors.Wrap(err, "failed to connect to server")
			return
		} else {
			fmt.Printf("\rretry connect to server after %d seconds", s)
		}

	}
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
	errCh := make(chan error, 1)
	go readRisks(c, recordId, out, errCh)

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

	err = <-errCh
	return
}

// readRisks receive response(s) containing risk found. it add recordId to the risk for correlation and
// writes it to the output file in json.
func readRisks(c pb.BluBracket_AnalyzeStreamClient, recordId string, out jsonstream.LineWriter, errCh chan error) {
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
		err = writeRisk(recordId, asResponse.Risk, out)
		if err != nil {
			return
		}
		riskCount++
	}
}

// writeRisk writes risk in json format to the output including recordId
func writeRisk(recordId string, risk *pb.Risk, out jsonstream.LineWriter) (err error) {
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
	err = out.Marshal(r)
	if err != nil {
		err = errors.Wrap(err, "failed writing risk to output")
		return
	}
	return
}

// record stores values for 'idColumn' and 'column' to be scanned for a row
type record struct {
	id   any
	text textType
}

// textType implements the Scanner interface required for custom type
// refer https://pkg.go.dev/database/sql#Scanner
type textType struct {
	b []byte
}

func (t *textType) Scan(rawData any) (err error) {
	//fmt.Printf("rawData type: %T\n", rawData)
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
