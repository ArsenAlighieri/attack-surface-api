# 1. Build aşaması
FROM golang:1.24-alpine AS builder


WORKDIR /app

# Sistem bağımlılıkları (örneğin, git)
RUN apk add --no-cache git

# Modül dosyalarını kopyala ve modülleri indir
COPY go.mod go.sum ./
RUN go mod download

# Proje dosyalarını kopyala
COPY . .

# Uygulamayı derle (main dosyanın yolu senin projene göre değişebilir)
RUN go build -o attack-surface-api ./main.go

# 2. Çalışma aşaması
FROM alpine:latest

WORKDIR /app

# Zaman dilimi ayarı (opsiyonel, loglar için)
RUN apk add --no-cache tzdata
ENV TZ=Europe/Istanbul

# Builder aşamasından derlenen binary'yi kopyala
COPY --from=builder /app/attack-surface-api .

# 8080 portunu expose et
EXPOSE 8080

# Uygulamayı çalıştır
CMD ["./attack-surface-api"]
