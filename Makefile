TARGET=evilginx
PACKAGES=core database log parser

.PHONY: all build clean install run secure

all: build

build:
	@go build -o ./build/$(TARGET) -mod=vendor main.go

clean:
	@go clean
	@rm -f ./build/$(TARGET)

install:
	@chmod +x install.sh
	@sudo bash install.sh

secure:
	@chmod +x build_secure.sh
	@sudo bash build_secure.sh

run:
	@export DISPLAY=:99 && sudo ./build/$(TARGET) -p ./phishlets -t ./redirectors
