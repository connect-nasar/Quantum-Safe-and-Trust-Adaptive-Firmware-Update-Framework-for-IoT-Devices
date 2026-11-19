module witness-quorum/engine

go 1.27.3

require (
	github.com/hyperledger/SmartBFT v0.0.0
	go.uber.org/zap v1.28.0
	google.golang.org/protobuf v1.36.12
)

require (
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
)

replace github.com/hyperledger/SmartBFT => ../vendor-source/SmartBFT
