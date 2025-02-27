CREATE TABLE signin (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    login_token UUID UNIQUE NOT NULL
);

CREATE TABLE snippets (
    id SERIAL PRIMARY KEY,
    snippet_id VARCHAR(10) UNIQUE NOT NULL,
    snippet TEXT NOT NULL,
    login_token UUID NOT NULL,
    visibility VARCHAR(10) CHECK (visibility IN ('private', 'public')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (login_token) REFERENCES signin(login_token) ON DELETE CASCADE
);
