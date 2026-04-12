# Flask JWT Auth API

A secure REST API with JWT authentication built with Flask.

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open `index.html` in your browser (serve alongside Flask or open directly).

## API Endpoints

| Method | Endpoint    | Auth     | Description              |
|--------|-------------|----------|--------------------------|
| GET    | /           | None     | Health check             |
| POST   | /register   | None     | Register new user        |
| POST   | /login      | None     | Login, returns JWT token |
| GET    | /profile    | Bearer   | Get authenticated profile|

## Environment Variables

```bash
export JWT_SECRET_KEY=your-secure-secret-key
```
