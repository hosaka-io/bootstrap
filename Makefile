all: build

build: bootstrap

bootstrap: ./bootstrap.go
	go build -o bootstrap ./bootstrap.go

run:
	go run ./bootstrap.go

clean:
	rm bootstrap

