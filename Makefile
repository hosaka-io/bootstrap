all: build

build: bootstrap

bootstrap: ./src/go/bootstrap.go
	go build -o bootstrap ./src/go/bootstrap.go

run:
	go run ./src/go/bootstrap.go

clean:
	rm bootstrap

