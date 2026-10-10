# DELTA.KEYS Multi-Panel starter

A starter app for a dark purple storefront with registration by referral code, balances, product catalog, and an admin area.

## Important limitations
- This starter does **not** connect to YTYAMRAJ OP. Automatic generation requires an authorized integration supplied/supported by that provider. This project deliberately does not automate a third-party admin page or store its login credentials.
- A referral balance is internal store credit, not payment processing.
- SQLite data may not persist across Railway deployments/restarts unless you attach a persistent volume and set `DB_PATH` to a path on that volume. For production, use a persistent database.
- Set `SESSION_SECRET` and `ADMIN_PASSWORD` in Railway Variables before exposing the site publicly.

## First run
`npm install && npm start`

On first startup, the app seeds a demo admin account using `ADMIN_USERNAME` (default `admin`) and `ADMIN_PASSWORD` (default `change-me-now`). Change these before use.

## Railway variables
- `SESSION_SECRET`: long random secret
- `ADMIN_USERNAME`: admin username
- `ADMIN_PASSWORD`: strong admin password
- `DB_PATH`: optional path to persistent SQLite database, e.g. `/data/delta.db`

This is a starter, not a payment-ready production system. Add provider-authorized key issuance and real payment verification before selling products.
