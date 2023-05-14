run:
	go run ./bintest

mainwasm:
	rm ./wasm/main.wasm
	GOOS=js GOARCH=wasm go build -o ./wasm/main.wasm ./bintest

webserver:
	echo http://localhost:9090/index.htm
	gondn_wasm_server -path ./wasm -port 9090
