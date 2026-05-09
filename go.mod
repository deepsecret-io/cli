module github.com/deepsecret-io/cli

go 1.26.2

require (
	github.com/deepsecret-io/sdk v0.0.0
	github.com/google/uuid v1.6.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/term v0.42.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/deepsecret-io/sdk => ../sdk

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)
