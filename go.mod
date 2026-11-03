module iprd

go 1.26.0

require (
	github.com/coder/websocket v1.8.14
	github.com/sagernet/sing v0.9.7-0.20261023115510-03a6cce64bf7
	golang.org/x/crypto v0.54.0
	golang.org/x/term v0.45.0
	howett.net/plist v1.0.1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/testify v1.12.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
)

require (
	github.com/cloudflare/circl v1.6.5
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.12
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/sagernet/quic-go => github.com/idawnlight/quic-go v0.61.0-sing-box-mod.12.0.20261103131650-91bb8838f25f
