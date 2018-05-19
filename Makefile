all: build

build: bootstrap encode

encode: encode.go
	go build -o encode encode.go

bootstrap: ./bootstrap.go
	go build -o bootstrap bootstrap.go

run:
	go run ./bootstrap.go

clean:
	rm bootstrap encode

