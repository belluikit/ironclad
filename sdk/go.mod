module github.com/belluikit/ironclad/sdk

go 1.26.2

require (
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.11.1
	github.com/trendvidia/protowire-go v1.0.0
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/sys v0.27.0
)

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// v0.2.0 cannot be downloaded: the repository's LICENSE and this
// module's license/ package collide in its zip on case-insensitive
// file systems.
retract v0.2.0
