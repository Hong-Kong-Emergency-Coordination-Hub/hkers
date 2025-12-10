# API Quick Reference

| Endpoint            | Method | Auth Header                  | Body / Payload      | Success Response (JSON) | Notes                            |
|---------------------|--------|------------------------------|---------------------|-------------------------|----------------------------------|
| `/auth/login`       | GET    | None                         | None                | 302 redirect            | Starts OIDC login flow           |
| `/auth/callback`    | GET    | None                         | Query: `code,state` | `access_token`, `user`  | Handles OIDC callback, issues JWT|
| `/auth/refresh`     | POST   | `Authorization: Bearer JWT`  | None                | `access_token`          | Refreshes JWT (no body)          |
| `/auth/logout`      | POST   | `Authorization: Bearer JWT`* | None                | `message`, `logout_url` | Client should discard its token  |
| `/user`             | GET    | `Authorization: Bearer JWT`  | None                | User claims             | Same as `/api/v1/me`             |
| `/api/v1/me`        | GET    | `Authorization: Bearer JWT`  | None                | User claims             | Protected profile endpoint       |
| `/health`           | GET    | None                         | None                | `status`                | Health check                     |

\*Auth header optional for logout; if present and provider supports, a logout URL is returned.

