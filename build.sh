go generate ./cmd/ingress-counter/ ./cmd/cusum-detector/
go build -o bin/ingress-counter  ./cmd/ingress-counter
go build -o bin/cusum-detector   ./cmd/cusum-detector