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

## CLI Usage

A command-line interface (CLI) is available to interact with the API.

### Installation
Ensure you have `click` and `requests` installed:
```sh
pip install click requests
```

Run the CLI script:
```sh
python cli.py <command> [options]
```

### Commands

- **Login:**
  ```sh
  python cli.py login <username> <password>
  ```
  Saves authentication token and public key.

- **Create Account:**
  ```sh
  python cli.py create-account <username> <password> <email>
  ```
  Registers a new user.

- **Upload Snippet:**
  ```sh
  python cli.py upload "Your snippet content here" --private
  ```
  Uploads a new snippet (use `--private` for private pastes).

- **Retrieve Snippet:**
  ```sh
  python cli.py get-snippet <snippet_id> --public-key <key>
  ```
  Fetches a snippet (include `--public-key` for private snippets).

- **Delete Snippet:**
  ```sh
  python cli.py delete <snippet_id>
  ```
  Deletes a snippet.

- **List Snippets:**
  ```sh
  python cli.py list
  ```
  Lists all snippets (public and private).

- **Logout:**
  ```sh
  python cli.py logout
  ```
  Removes authentication token.

## Other Details

- The API runs on `http://localhost:5000`.
- Default PostgreSQL and Redis configurations are provided in `docker-compose.yml`.
- Ensure Docker and Docker Compose are installed before running the commands.

---

For further configurations, modify `config.py` or update `docker-compose.yml` as needed.


