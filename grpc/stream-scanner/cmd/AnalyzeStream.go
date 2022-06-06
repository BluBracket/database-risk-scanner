package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	pb "github.com/database-risk-scanner/grpc/api"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var streamName string

// analyzeStreamCmd represents the analyze-stream command
var analyzeStreamCmd = &cobra.Command{
	Use:   "analyze-stream <target-server>",
	Short: "Analyze data on input stream",
	Long: `Invokes AnalyzeStream API on a local gRPC server. For example:

	cat path/to/file | stream-scanner analyze-stream --stream-name <name-of-stream> <target-path-for-blubracket-grpc-server>
	cat ~/logs/a.log | stream-scanner analyze-stream --stream-name log1 unix:/tmp/test.blubracket-cli-server-123
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return analyzeStream(args[0])
	},
	Args: cobra.ExactValidArgs(1),
}

func analyzeStream(target string) error {
	// connect and create client
	conn, e := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		fmt.Printf("Connection failed: %v\n", e)
		return e
	}
	defer conn.Close()
	c := pb.NewBluBracketClient(conn)
	asClient, e := c.AnalyzeStream(context.Background())
	if e != nil {
		fmt.Printf("AnalyzeStream call failed: %v\n", e)
		return e
	}

	// send stream name
	err := asClient.Send(&pb.AnalyzeStreamRequest{
		Metadata: &pb.AnalyzeStreamMetadata{StreamName: streamName}})
	if err != nil {
		fmt.Printf("failed to send streamname msg: %v\n", err)
		return err
	}

	done := make(chan bool)

	// receive risks
	go readRisks(asClient, done)

	// send data
	reader := os.Stdin
	b := make([]byte, 1024)
	for {
		n, err := reader.Read(b)
		if n > 0 {
			err := asClient.Send(&pb.AnalyzeStreamRequest{Data: b[:n]})
			if err != nil {
				fmt.Printf("failed to send data to server : %v\n", err)
				return err
			}
		}
		if err == io.EOF {
			asClient.CloseSend()
			break
		}
		if err != nil {
			fmt.Printf("failed to read data from stdin: %v\n", err)
			return err
		}
	}
	<-done
	return nil
}

func readRisks(c pb.BluBracket_AnalyzeStreamClient, done chan<- bool) {
	defer close(done)
	for {
		asResponse, e := c.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			fmt.Printf("failed while receiving data from server: %v\n", e)
			return
		}
		fmt.Println(asResponse.Risk)
	}
}

func init() {
	rootCmd.AddCommand(analyzeStreamCmd)
	analyzeStreamCmd.Flags().StringVarP(&streamName, "stream-name", "s", "untitled", "Name of stream")
}
