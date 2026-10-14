module github.com/belluikit/ironclad/devsdk

go 1.26.2

require (
	github.com/belluikit/ironclad/sdk v0.0.0
	github.com/stretchr/testify v1.11.1
	github.com/trendvidia/protowire-go v1.0.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/belluikit/ironclad/sdk => ../sdk
