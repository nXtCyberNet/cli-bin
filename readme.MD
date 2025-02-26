# Code Snippet Manager

A simple API-based code snippet manager built with Flask, PostgreSQL, and Redis for authentication and storage.

## Project Type

- **Backend API**
- **Flask (Python)**
- **PostgreSQL** (for storing snippets and user data)
- **Redis** (for session management and caching)
- **Dockerized** (Docker Compose for easy deployment)

## Running with Docker Compose

1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/code-snippet-manager.git
   cd code-snippet-manager
   ```

2. Build and start the containers:
   ```sh
   docker-compose up --build -d
   ```

3. Stop the containers:
   ```sh
   docker-compose down
   ```

## Environment Variables

Create a `.env` file with the following variables:
```env
DB_NAME=snippets
DB_USER=admin
DB_PASSWORD=secret
DB_HOST=db
DB_PORT=5432
REDIS_HOST=redis
REDIS_PORT=6379
SECRET_KEY=your_secret_key
```

## Other Details

- The API runs on `http://localhost:5000`.
- Default PostgreSQL and Redis configurations are provided in `docker-compose.yml`.
- Ensure Docker and Docker Compose are installed before running the commands.

---

For further configurations, modify `config.py` or update `docker-compose.yml` as needed.

