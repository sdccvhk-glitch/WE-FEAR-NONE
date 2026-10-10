DELTA.KEYS Multi-Panel update

Changes:
- Admin login is tucked inside the main login screen under the "Admin login" toggle.
- Admins use the same username/password form; successful login identifies the role and shows the Admin panel in the dashboard navigation.
- Dashboard buttons are arranged in a responsive side menu that becomes a compact grid on phones.
- Customer registration is separate and requires a valid referral code.

Default admin credentials only apply to a fresh database:
username: admin
password: change-me-now

Before public deployment set ADMIN_PASSWORD, ADMIN_USERNAME and a strong random SESSION_SECRET in Railway Variables. Use persistent storage for SQLite (set DB_PATH to a persistent volume path).
Provider/YTYAMRAJ OP automatic key generation is NOT connected. Order workflow currently records pending orders and allows authorized admin manual delivery.
