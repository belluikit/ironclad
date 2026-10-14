module github.com/belluikit/ironclad/devsdk

go 1.26.2

require (
	github.com/belluikit/ironclad/sdk v0.0.0
	github.com/trendvidia/protowire-go v1.0.0
)

require (
	github.com/stretchr/testify v1.11.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/belluikit/ironclad/sdk => ../sdk
