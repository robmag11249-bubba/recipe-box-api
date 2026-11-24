This is a first-pass security review based on the current code and routes on 127.0.0.1:5000.”

# Security Audit – Recipe API

Date: 2026-11-24  
Auditor: Robert Mangum

## Scope

Audit of the existing Flask-based Recipe API focused on:

- **Safe storage** of user credentials
- **Identity (authentication)** protections on write operations
- **Access control (authorization)** for recipe data
- Verification of behavior using live `curl` requests and direct DB inspection

The audit is evidence-based: each check records the request, response, and conclusion.

---

## 1. Safe Storage

### 1.1 User password storage

**Check:** Inspect the `users` table schema.

```sql
PRAGMA table_info(users);

Observed:


id – INTEGER
username – TEXT
email – TEXT
password_hash – TEXT

Conclusion:

Passwords are stored in a password_hash column, not in a password column. This suggests hashed storage, not plaintext.

1.2 Existing user password hashes

Check: Inspect stored credentials for existing users.

SQL
SELECT id, username, email, password_hash
FROM users
LIMIT 3;
Observed examples:


robert → password_hash like
scrypt:32768:8:1$DP6kUQNvfqXPmJkm$...
nonowner → password_hash like
scrypt:32768:8:1$0JXJjhsMGOBf9zVR$...

All values are long scrypt:...$...$... strings, not human-readable passwords.


Conclusion:

PASS – Safe storage. Existing user passwords are stored as scrypt hashes, not plaintext.

1.3 New user registration storage

Check: Register a new user through the API and inspect the stored record.


Request:

Bash
curl -i -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser1", "email": "t1@example.com", "password": "testpass"}'
Response:


Status: 201 CREATED
Body: {"message": "user registered"}

DB inspection:

SQL
SELECT id, username, email, password_hash
FROM users
WHERE username = 'testuser1';
Observed:


username: testuser1
email: t1@example.com
password_hash: scrypt:32768:8:1$BLGHp2...$ec27e5... (long scrypt hash)

Conclusion:

PASS – Safe storage on new registrations. Registration flow stores only hashed passwords using scrypt.

2. Identity (Authentication)
2.1 Anonymous protected write

Check: Attempt to create a recipe without any Authorization header.


Request:

Bash
curl -i -X POST http://127.0.0.1:5000/recipes \
  -H "Content-Type: application/json" \
  -d '{"title": "Anon Recipe", "instructions": "No auth"}'
Response:


Status: 401 UNAUTHORIZED
Body: {"error": "missing or invalid Authorization header"}

Conclusion:

PASS – Protected write requires authentication. Anonymous users cannot create recipes; the API correctly returns 401 when no auth header is present.

2.2 Login / token endpoint

Check: Discover and call any login or token endpoint (e.g. /login, /auth/login, /token).


Evidence:


Listing routes via:

curl -s http://127.0.0.1:5000/routes | python -m json.tool
Observed routes:

/recipes
/recipes/<int:recipe_id>
/register
/routes
/static/<path:filename>

Observed:


No /login, /auth/login, or /token route is registered in the running app.
As a result, there is currently no way for clients to obtain a JWT or similar token via the API.

Conclusion:

FAIL / GAP – No active login endpoint.

Although the codebase contains a @app.post("/login") function, the running app exposes no login route. This means:


Users can be created (/register),
But there is no API-provided way for them to authenticate and obtain credentials for protected actions.

This blocks full end-to-end testing of owner/admin behaviors and is a required fix for real deployment.

3. Access Control (Authorization)
3.1 Anonymous read of recipes

Check: List recipes without authentication.


Request:

Bash
curl -i http://127.0.0.1:5000/recipes
Response:


Status: 200 OK

Body: JSON array including:

Public recipes, e.g.:
"title": "Overnight oats", "is_public": true, ...
A private recipe:
"title": "Secret family hot sauce", "is_public": false, ...

Observed:


Anonymous users can see all recipes, including at least one with "is_public": false.

Conclusion:

FAIL – Private data exposed to anonymous users.

The GET /recipes endpoint does not filter out non-public recipes for anonymous users. A recipe explicitly marked is_public: false is returned in the anonymous listing, which violates expected confidentiality for private content.

3.2 Anonymous modification / deletion

Note:

Due to the missing login/token endpoint, authenticated owner and admin behaviors could not be tested. As a result:


Attempts to test cross-user recipe modification/deletion, owner-only updates, and admin-only actions were not possible in this audit.
Only anonymous behavior on POST /recipes and GET /recipes could be confirmed.
4. Summary
Strengths:


Password storage is safe.
All users use a password_hash column with long scrypt hashes.
New registrations also store only hashed passwords (no plaintext observed).
Anonymous writes are blocked.
POST /recipes without auth reliably returns 401 UNAUTHORIZED with a clear error message.

Gaps / Risks:


No active login / token endpoint

There is no exposed route to authenticate users and issue tokens.
This prevents legitimate users from performing authenticated actions and prevents full testing of owner/admin permissions.
Private recipes visible to anonymous users

GET /recipes returns recipes with is_public: false to anonymous callers.
This leaks private data and represents a broken access control issue on read endpoints.

Overall conclusion:


Safe storage protections are in place and working.
Authentication is partially enforced (writes require auth) but cannot be fully used due to a missing login endpoint.
Access control for reads is currently insufficient: anonymous users can see non-public recipes.