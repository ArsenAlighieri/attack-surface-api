# Attack Surface API

Attack Surface API is a powerful REST API application built with Go and designed for security research and reconnaissance. It provides core functionalities for managing domains and subdomains, including advanced scanning capabilities integrated with external services like crt.sh, VirusTotal, and Shodan. The application is containerized with Docker for easy setup and deployment.

## Features

*   **Domain and Subdomain Management:** Add, list, and delete domains, and view associated subdomains.
*   **User Authentication:** Secure user registration and login with JWT-based authentication.
*   **Advanced Subdomain Scanning:**
    *   Utilizes a default wordlist for brute-force subdomain discovery.
    *   Supports custom wordlists provided by the user.
    *   Integrates with **crt.sh** for Certificate Transparency log analysis.
    *   Integrates with **VirusTotal** for additional subdomain data (requires API key).
    *   Integrates with **Shodan** for network intelligence-based subdomain discovery (requires API key).
*   **Scan Status Tracking:** Monitor the progress of subdomain scans (pending, scanning, completed, error).
*   **High Performance:** Built with the Fiber web framework for efficient API handling.
*   **Database Integration:** Uses MySQL for data storage with GORM as the ORM.
*   **Containerized Deployment:** Easy setup and execution using Docker and Docker Compose.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed on your system:

*   [**Docker**](https://docs.docker.com/get-docker/)
*   [**Docker Compose**](https://docs.docker.com/compose/install/)

### Installation and Running

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ArsenAlighieri/attack-surface-api.git
    cd attack-surface-api
    ```

2.  **Configure Environment Variables:**
    Open the `docker-compose.yml` file in the project root. You need to set the following environment variables under the `api` service:

    *   `JWT_SECRET`: **REQUIRED.** Replace `"your-super-secret-key"` with a strong, unique secret key. This is crucial for the security of your JWT tokens.
    *   `VIRUSTOTAL_API_KEY`: **OPTIONAL.** If you have a VirusTotal API key, replace `"your-virustotal-api-key"` with your actual key. If left empty, VirusTotal scans will be skipped.
    *   `SHODAN_API_KEY`: **OPTIONAL.** If you have a Shodan API key, replace `"your-shodan-api-key"` with your actual key. If left empty, Shodan scans will be skipped.

    Example `docker-compose.yml` snippet (after modification):
    ```yaml
        api:
          build: .
          container_name: attack-surface-api
          environment:
            DB_USER: asmuser
            DB_PASS: asmuserpassword
            DB_HOST: db
            DB_PORT: 3306
            DB_NAME: attack-surface
            JWT_SECRET: "your-actual-strong-jwt-secret-key-here" # <--- CHANGE THIS
            VIRUSTOTAL_API_KEY: "your-actual-virustotal-api-key" # <--- OPTIONAL: Add your key
            SHODAN_API_KEY: "your-actual-shodan-api-key" # <--- OPTIONAL: Add your key
          depends_on:
            - db
          ports:
            - "8080:8080"
    ```

3.  **Build and start the services:**
    ```bash
    docker-compose up --build -d
    ```
    This command will:
    *   Build the Docker image for the API service.
    *   Create and start the `asm-mysql` (MySQL database) and `attack-surface-api` (Go API) containers.
    *   The API will be accessible at `http://localhost:8080`.

## API Endpoints

The API provides the following endpoints. All protected routes require a JSON Web Token (JWT) in the `Authorization` header (e.g., `Authorization: Bearer YOUR_JWT_TOKEN`).

### Public Routes

*   **`POST /api/register`**
    *   Registers a new user.
    *   **Body:** `{"email": "user@example.com", "password": "yourpassword"}`

*   **`POST /api/login`**
    *   Authenticates a user and returns a JWT token.
    *   **Body:** `{"email": "user@example.com", "password": "yourpassword"}`
    *   **Response:** `{"token": "YOUR_JWT_TOKEN"}`

### Protected Routes

*   **`GET /api/profile`**
    *   Retrieves the authenticated user's profile information.

*   **`POST /api/domains`**
    *   Adds a new domain for scanning.
    *   **Body:** `{"name": "example.com", "wordlist": ["sub1", "sub2"]}` ( `wordlist` is optional; if omitted, a default wordlist is used.)

*   **`GET /api/domains`**
    *   Lists all domains associated with the authenticated user, including their subdomains.

*   **`DELETE /api/domains/:id`**
    *   Deletes a domain by its ID.
    *   Replace `:id` with the actual domain ID.

*   **`GET /api/domains/:id/subdomains`**
    *   Lists all discovered subdomains for a specific domain.
    *   Replace `:id` with the actual domain ID.

*   **`GET /api/domains/:id/status`**
    *   Retrieves the current scanning status of a specific domain.
    *   Replace `:id` with the actual domain ID.
    *   **Response:** `{"status": "pending" | "scanning" | "completed" | "error"}`

## Usage Examples (using `curl`)

First, ensure your API is running as described in "Installation and Running".

### 1. Register a User

```bash
curl -X POST http://localhost:8080/api/register \
-H "Content-Type: application/json" \
-d '{"email": "test@example.com", "password": "password123"}'
```

### 2. Login and Get JWT Token

```bash
curl -X POST http://localhost:8080/api/login \
-H "Content-Type: application/json" \
-d '{"email": "test@example.com", "password": "password123"}'
# Save the "token" from the response for subsequent requests
```

### 3. Add a Domain (with default wordlist)

```bash
YOUR_JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # Replace with your actual token
curl -X POST http://localhost:8080/api/domains \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $YOUR_JWT_TOKEN" \
-d '{"name": "example.com"}'
# Note the "ID" of the created domain from the response
```

### 4. Add a Domain (with custom wordlist)

```bash
YOUR_JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # Replace with your actual token
curl -X POST http://localhost:8080/api/domains \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $YOUR_JWT_TOKEN" \
-d '{"name": "testdomain.com", "wordlist": ["dev", "api", "blog"]}'
```

### 5. List Domains

```bash
YOUR_JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # Replace with your actual token
curl -X GET http://localhost:8080/api/domains \
-H "Authorization: Bearer $YOUR_JWT_TOKEN"
```

### 6. Get Domain Scan Status

```bash
YOUR_JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # Replace with your actual token
DOMAIN_ID="1" # Replace with the actual ID of your domain
curl -X GET http://localhost:8080/api/domains/$DOMAIN_ID/status \
-H "Authorization: Bearer $YOUR_JWT_TOKEN"
```

### 7. Get User Profile

```bash
YOUR_JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # Replace with your actual token
curl -X GET http://localhost:8080/api/profile \
-H "Authorization: Bearer $YOUR_JWT_TOKEN"
```

### 8. Delete a Domain

```bash
YOUR_JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # Replace with your actual token
DOMAIN_ID="1" # Replace with the actual ID of your domain
curl -X DELETE http://localhost:8080/api/domains/$DOMAIN_ID \
-H "Authorization: Bearer $YOUR_JWT_TOKEN"
```

## Project Structure

```
.
├── docker-compose.yml       # Docker Compose configuration
├── Dockerfile               # Dockerfile for the Go API service
├── go.mod                   # Go module dependencies
├── go.sum                   # Go module checksums
├── main.go                  # Main application entry point
├── README.md                # This documentation file
└── internal/
    ├── api/                 # API handlers, middleware, and routes
    │   ├── handlers.go
    │   ├── middleware.go
    │   └── routes.go
    ├── database/            # Database connection and migration logic
    │   └── db.go
    ├── models/              # GORM database models (User, Domain, Subdomain)
    │   ├── domain.go
    │   ├── models.go
    │   └── subdomain.go
    └── services/            # Core business logic, including subdomain scanning
        ├── scanner.go
```

## Stopping the Application

To stop the running Docker containers and remove their resources:

```bash
docker-compose down
```