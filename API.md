# API Workshop: CRUD and Request/Response Guide

## 1) What is an API?
An **API** (Application Programming Interface) is a way for one application to communicate with another using defined rules.
In this workshop, you call HTTP endpoints (URLs) and the server returns JSON responses.

For example:
- Client sends request: `POST /api/auth/token`
- Server returns response: token JSON or error JSON

---

## 2) What are CRUD methods?
CRUD is the most common pattern for data operations:

- **Create** → `POST` (create a new record)
- **Read** → `GET` (retrieve data)
- **Update** → `PUT` (modify an existing record)
- **Delete** → `DELETE` (remove a record)

### How this workshop maps to CRUD
- **Read**: `GET /api/task1` (retrieve your `task_id`)
- **Create**: `POST /api/task2` (create a task record)
- **Update**: `PUT /api/task3/<task_record_id>` (update your record)
- **Delete**: `DELETE /api/task4` (delete by `action_id` to complete flow)

---

## 3) End-to-end workshop flow
1. **Get token** using your API key:
   - `POST /api/auth/token`
2. **Task 1** get your task ID:
   - `GET /api/task1`
3. **Task 2** save task record:
   - `POST /api/task2`
4. **Task 3** update record:
   - `PUT /api/task3/<task_record_id>`
5. **Task 4** delete/finalize:
   - `DELETE /api/task4`

If successful, final response includes `certification_id`.

---

## 4) How an API request is structured
A request usually has:
1. **Method** (`GET`, `POST`, `PUT`, `DELETE`)
2. **URL** (endpoint)
3. **Headers** (metadata such as auth and content type)
4. **Body** (JSON payload, usually for POST/PUT/DELETE in this workshop)

### Common headers in this project
- `Content-Type: application/json`
- `Authorization: Bearer <JWT_TOKEN>` for protected endpoints
- `X-Admin-Password: workshop_admin_pass` for admin endpoint only (`/admin/add_user`)

### Example request
```bash
curl -X POST http://localhost:5000/api/task2 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"task_id":"YOUR_TASK_ID"}'
```

---

## 5) Typical API responses
This project returns JSON with a consistent style, usually including:
- `status` (HTTP-like code)
- success fields (`token`, `task_id`, `task_record_id`, `action_id`, `certification_id`)
- or error fields (`message`, `error_code`)

### Success example
```json
{
  "status": 201,
  "task_record_id": 123,
  "message": "Task saved successfully",
  "next_endpoint": "/api/task3/123"
}
```

### Error example
```json
{
  "status": 401,
  "message": "Token is missing",
  "error_code": "TOKEN_MISSING"
}
```

---

## 6) API keys, tokens, and common security setup

## API key vs token
- **API key**: long-lived identifier for the user; used to request a token.
- **JWT token**: short-lived credential used on protected endpoints.

In this workshop:
- Token is obtained from `POST /api/auth/token` with `api_key`.
- Token lifetime is short (about 5 minutes).
- Protected routes enforce `Authorization: Bearer <token>`.

## Common real-world setup (general)
Most APIs use one or more of these patterns:
- API keys for service identification
- Bearer tokens (JWT or opaque token) for session/auth
- OAuth2/OpenID Connect for delegated authentication
- HTTPS/TLS for encryption in transit
- Token expiration + refresh strategy
- Role/permission checks (authorization)
- Audit logging for traceability

## How security works in this project
- JWT signature is validated.
- Token must exist in DB and be active.
- Expired tokens are rejected.
- User from token must exist.
- Ownership checks prevent cross-user task manipulation.
- Audit logs capture actions, endpoint, status, and request metadata.

> Note: This workshop keeps secrets/passwords in code for learning convenience. In production, use env vars, secret vaults, rotation, and stronger hardening.

---

## 7) What is parsing?
**Parsing** means reading and interpreting input data into a usable structure.

Examples in this API:
- Parsing JSON body via `request.get_json()`
- Parsing `Authorization` header to extract `Bearer <token>`
- Parsing URL path params like `task_record_id` in `/api/task3/<task_record_id>`

If parsing fails or required fields are absent, the API returns validation errors.

---

## 8) Basic errors users commonly encounter

- `MALFORMED_JSON`: Body is not valid JSON.
- `API_KEY_REQUIRED`: Missing `api_key` in token request.
- `INVALID_API_KEY`: API key is wrong or unknown.
- `TOKEN_MISSING`: No Authorization header/token.
- `TOKEN_INVALID`: Token malformed or not active.
- `TOKEN_EXPIRED`: Token expired; request a new one.
- `TASK_ID_REQUIRED`: Missing `task_id` for Task 2.
- `INVALID_TASK_ID`: Task ID does not belong to current user.
- `TASK_NOT_FOUND`: Task record/action not found or not owned by user.
- `ACTION_ID_REQUIRED`: Missing `action_id` for Task 4.
- `NOT_FOUND`: Wrong route/endpoint.
- `SERVER_ERROR`: Unexpected backend error.

Quick troubleshooting:
1. Verify endpoint URL and HTTP method.
2. Verify headers (`Content-Type`, `Authorization`).
3. Verify JSON keys and spelling (case-sensitive).
4. Regenerate token if expired.
5. Complete workshop steps in order.

---

## 9) FAQ (Most Frequently Asked Questions)

### Q1: Why do I get 401 Unauthorized?
Usually because token is missing, invalid, or expired. Add `Authorization: Bearer <token>` and regenerate token if needed.

### Q2: Why does token endpoint return 404 INVALID_API_KEY?
The API key is not recognized. Check the value exactly as provided by the instructor/admin.

### Q3: Why does Task 2 say `INVALID_TASK_ID`?
You must send **your own** `task_id` returned by `GET /api/task1` with the same authenticated user.

### Q4: Why does Task 3 or Task 4 return `TASK_NOT_FOUND`?
The `task_record_id` or `action_id` may be wrong, from another user, or not created in prior step.

### Q5: Do I always need `Content-Type: application/json`?
For JSON body endpoints, yes. It helps the server parse body correctly.

### Q6: How do I know what to call next?
Success responses include `next_endpoint` for guided progression.

### Q7: Can I reuse an old token?
Only while it is valid and active. In this workshop, token TTL is short, so request a new token frequently.

### Q8: What status codes should I expect?
- `200` success (GET/PUT/DELETE)
- `201` created (POST task create)
- `400` bad request/validation
- `401` auth issues
- `404` not found
- `500` server error

### Q9: Where can I inspect all endpoints interactively?
Open Swagger UI: `/hidden/swagger/`.

### Q10: Is this production-ready security?
No. It is workshop-grade. Production should use secure secret management, HTTPS everywhere, tighter auth policies, monitoring, and rate limits.

---

## 10) Quick reference (minimal sequence)
```bash
# 1) Get token
POST /api/auth/token

# 2) Read
GET /api/task1

# 3) Create
POST /api/task2

# 4) Update
PUT /api/task3/<task_record_id>

# 5) Delete
DELETE /api/task4
```

You can pair this file with `WORKSHOP_INSTRUCTIONS.md` and `curl_commands_windows.txt` for command-ready examples.
