### Steps to re-generate api.pb.go, api_grpc.pb.go

Pre-requisites:

1. protoc compiler is installed
2. protocol compiler plugins for Go are installed as per steps in the [quickstart][1]

Steps to re-generate:

```
1. cd ./grpc
2. run protoc compiler to regenerate files. 

protoc --go_out=. --go_opt=paths=source_relative \
--go-grpc_out=. --go-grpc_opt=paths=source_relative \
api/api.proto
```

[1]: https://grpc.io/docs/languages/go/quickstart/ 



