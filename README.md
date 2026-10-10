# DELTA.KEYS Multi-Panel — fixed login starter

- Separate Login and Create Account views.
- Successful login/register uses the returned user object to open the dashboard.
- Adds `credentials: same-origin` to API requests and explicitly saves the server session after login.
- Admin products, referral codes, balances, order history, and manual key-delivery workflow.

Before production:
- Set a strong `ADMIN_PASSWORD` and random `SESSION_SECRET` in Railway Variables.
- Configure persistent storage and `DB_PATH` for SQLite.
- This does not connect to YTYAMRAJ OP. Key generation requires an authorized supported integration.
- This is a starter, not a fully audited production payment system.
