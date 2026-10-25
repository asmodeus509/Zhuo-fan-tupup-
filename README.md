ZHUO FAN HT — Guide vidéo + chaîne

Run: python server.py (localhost:8765). Deploy behind HTTPS with reverse proxy and authentication.

POST /api/admin/guide — JSON {"channel":"https://..."} with Authorization: Bearer <admin_session_token>
PUT /api/admin/guide-video — raw MP4/WebM bytes (max 50 MB) with Content-Type and Bearer admin token.
GET /api/guide — public JSON with channel and video path.
GET /api/guide-video — public video.

Admin must first register/login and be granted admin privileges as explained in the previous backend package.
IMPORTANT: Frontend HTML is still mostly a local demo, and its admin panel is not a real authenticated server admin. Deploying requires serving HTML and API from the same HTTPS origin, integrating the frontend's login, and reviewing security before production.
