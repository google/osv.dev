protoc -I=proto --go_out=. proto/config.proto
go mod tidy
go build