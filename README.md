# Attack Surface API

Attack Surface API, güvenlik araştırmaları ve keşif (reconnaissance) için geliştirilmiş, Go diliyle yazılmış ve Docker ile kolayca çalıştırılabilen bir REST API uygulamasıdır. Proje, domain ve subdomain yönetimi gibi temel özellikleri içerir.

---

## Özellikler

- Domain ve Subdomain yönetimi  
- MySQL veritabanı kullanımı  
- Fiber web framework ile yüksek performanslı API  
- Docker ve Docker Compose ile hızlı kurulum ve çalıştırma  

---

## Başlangıç

### Gereksinimler

- Docker  
- Docker Compose  

### Kurulum ve Çalıştırma

1. Depoyu klonlayın:

git clone https://github.com/ArsenAlighieri/attack-surface-api.git
cd attack-surface-api

    Docker Compose ile proje konteynerlerini oluşturup başlatın:

docker-compose up --build -d

    API artık http://localhost:8080 adresinde çalışıyor.

Proje Yapısı

    main.go — Uygulamanın giriş noktası

    models/ — GORM modelleri (Domain, Subdomain vb.)

    internal/database/ — Veritabanı bağlantı ve migrasyonlar

    docker-compose.yml — Docker servis tanımları

Veritabanı

MySQL kullanır. Docker Compose ile MySQL servisi otomatik başlatılır ve attack-surface adlı veritabanı oluşturulur.
API Endpoints (Örnek)

    GET /domains — Domain listesini getirir

    POST /domains — Yeni domain ekler

    GET /domains/:id — Domain detaylarını getirir

    PUT /domains/:id — Domain günceller

    DELETE /domains/:id — Domain siler

Yayına Alma (Deployment)

Projeyi internet ortamında çalıştırmak için:

    Bir VPS veya PaaS hizmeti edinin

    Projeyi sunucuya yükleyin

    Docker Compose ile çalıştırın

    Gerekirse Nginx veya Traefik ile reverse proxy ve HTTPS yapılandırması yapın
