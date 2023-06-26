# go-call-rust-ffi

Example demonstrate how to call Rust function from Golang

```
cd rustdemo
cargo build --release
cd ..

cp rustdemo/target/release/librustdemo.dylib ./lib

go build -o go-rust  -ldflags="-r ./lib" main.go

echo -n "hello" | shasum -a 256

./go-rust "hello" 

```
