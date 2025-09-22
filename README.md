# Assignment-devtown

# Node.js Authentication Assignment

## 📌 Overview
This project is a simple **Node.js + Express** server that demonstrates:
1. **Password Hashing Authentication** using `bcrypt`.
2. **JWT Authentication** for secure user login and protected routes.

It is part of the **Dev Town Assignment** on Authentication.

---

## ⚙️ Features
- User **registration** with hashed passwords.
- User **login** with password verification.
- JWT token generation on successful login.
- **Protected route** accessible only with a valid token.

---

## 🚀 Routes

### 1. Register
**POST** `/register`  
Registers a new user.

**Request Body:**
```json
{
  "username": "john",
  "password": "mypassword"
}


{ "message": "User registered successfully" }

{
  "username": "john",
  "password": "mypassword"
}
Authorization: Bearer <your-jwt-token>
{ "message": "Welcome john" }

{ "message": "Unauthorized or expired token" }
