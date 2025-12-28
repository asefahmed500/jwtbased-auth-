# Postman Testing Guide - JWT Auth Lab

Follow these steps to verify all authentication and authorization features.

## Base URL
`http://localhost:3000`

---

## 1. User Registration
**Endpoint:** `POST /register`  
**Description:** Creates a new user in the system.

**Body (JSON):**
```json
{
  "username": "postman_user",
  "password": "password123",
  "role": "student"
}
```
**Expected Response:** `201 Created` with the user object.

---

## 2. Login
**Endpoint:** `POST /login`  
**Description:** Authenticates user and returns Access and Refresh tokens.

**Body (JSON):**
```json
{
  "username": "postman_user",
  "password": "password123"
}
```
**Expected Response:** `200 OK`. 
> **Important:** Copy the `accessToken` for use in the next steps. Note that `accessToken` and `refreshToken` are also set as **HttpOnly Cookies**.

---

## 3. Access Protected Profile
**Endpoint:** `GET /profile`  
**Description:** Verifies that the Access Token works.

**Header:** 
- `Authorization`: `Bearer <YOUR_ACCESS_TOKEN>`

**Expected Response:** `200 OK` with your user profile details.

---

## 4. Access Dashboard (Students & Admins)
**Endpoint:** `GET /dashboard`  
**Description:** Verifies access for all authenticated users.

**Header:** 
- `Authorization`: `Bearer <YOUR_ACCESS_TOKEN>`

**Expected Response:** `200 OK`.

---

## 5. Role-Based Access Control (Admin Only)
**Endpoint:** `GET /admin`  
**Description:** Tests restriction for non-admin users.

**Header:** 
- `Authorization`: `Bearer <YOUR_ACCESS_TOKEN>` (using the student token from Step 2)

**Expected Response:** `403 Forbidden` ("Access denied. Admin role required.")

---

## 6. Token Refresh
**Endpoint:** `POST /refresh`  
**Description:** Uses the Refresh Token to generate a new Access Token.

**Body (JSON):**
```json
{
  "refreshToken": "<YOUR_REFRESH_TOKEN>"
}
```
**Expected Response:** `200 OK` with a new `accessToken`.

---

## 7. Logout & Token Invalidation
**Endpoint:** `POST /logout`  
**Description:** Blacklists the current token and clears cookies.

**Header:** 
- `Authorization`: `Bearer <YOUR_ACCESS_TOKEN>`

**Body (JSON):**
```json
{
  "refreshToken": "<YOUR_REFRESH_TOKEN>"
}
```
**Expected Response:** `200 OK`.

---

## 8. Error Case Testing (Verify 400/401/403)

### A. Missing Body (400 Bad Request)
- **Endpoint:** `POST /login`
- **Body:** `{}` (Empty object)
- **Expected:** `400 Bad Request` ("Username and password are required")

### B. Missing Token (401 Unauthorized)
- **Endpoint:** `GET /profile`
- **Headers:** Remove Authorization header.
- **Expected:** `401 Unauthorized` ("Access token is missing")

### C. Blacklisted Token (403 Forbidden)
- **Endpoint:** `GET /profile`
- **Header:** Use the token from Step 7 (after logout).
- **Expected:** `403 Forbidden` ("Token has been invalidated")
