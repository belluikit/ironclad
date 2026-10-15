module github.com/belluikit/ironclad/sdk

go 1.26.2

require (
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.12.1
	github.com/trendvidia/protowire-go v1.8.1
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/sys v0.49.0
)

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// v0.2.0 cannot be downloaded: the repository's LICENSE and this
// module's license/ package collide in its zip on case-insensitive
// file systems.
retract v0.2.0
