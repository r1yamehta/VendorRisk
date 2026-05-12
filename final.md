Theoretical Architecture & Implementation Plan
Overview: Split Authentication Architecture
text
┌─────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (HTML/CSS/JS)                       │
│                              Port 3000                               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
        ┌──────────────────────┐        ┌──────────────────────┐
        │   NODE.JS BACKEND    │        │  PYTHON BACKEND      │
        │      Port 5001       │        │     Port 5000        │
        ├──────────────────────┤        ├──────────────────────┤
        │ • User Authentication│        │ • Six Pillar Analysis│
        │ • Session Management │        │ • Risk Scoring       │
        │ • Database (vendors) │        │ • Email Notifications│
        │ • Vendor CRUD        │        │ • Password Reset     │
        │ • Alert Storage      │        │ • Email Verification │
        └──────────────────────┘        └──────────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                          ┌─────────────────────┐
                          │   SQLite Database   │
                          │   (vendors.db)      │
                          │   + users table     │
                          └─────────────────────┘
Phase 1: Database Schema Expansion (Node.js)
What You Need to Add to Your SQLite Database
Current tables: vendors, vendor_history, risk_alerts

New tables to create:

Table Name	Purpose	Key Columns
users	Store user credentials and profile	id, username, email, password_hash, is_verified, created_at, last_login
sessions	Track active user sessions	id, user_id, token, expires_at, created_at
email_queue	Store emails to be sent by Python	id, recipient_email, subject, body, status, created_at, sent_at
user_preferences	Email notification settings	user_id, alert_on_high_risk, alert_on_critical, digest_frequency
alert_subscriptions	Which vendors user wants alerts for	user_id, vendor_id, alert_threshold (risk score level)
Phase 2: Node.js Authentication Implementation
What Node.js Will Handle
2.1 User Registration Flow
text
User submits registration form
       │
       ▼
Node.js validates input (username, email, password)
       │
       ▼
Check if user already exists in `users` table
       │
       ▼
Hash password using bcrypt
       │
       ▼
Store user in database with is_verified = FALSE
       │
       ▼
Generate email verification token (JWT or random string)
       │
       ▼
Insert into `email_queue` table (status = 'pending')
       │
       ▼
Return success message to frontend
       │
       ▼
Python backend (runs every 5 minutes) → processes email_queue → sends verification email
2.2 Login Flow
text
User submits login credentials
       │
       ▼
Node.js looks up user by username/email
       │
       ▼
Compare password with stored hash using bcrypt
       │
       ▼
If valid: Generate session token (UUID or JWT)
       │
       ▼
Store session in `sessions` table with expiration (e.g., 7 days)
       │
       ▼
Set HTTP-only cookie in response
       │
       ▼
Return user info (without password) to frontend
2.3 Session Validation (Protected Routes)
text
Frontend sends request with session cookie
       │
       ▼
Node.js middleware checks `sessions` table for valid token
       │
       ▼
If token exists and not expired → get user_id
       │
       ▼
Attach user object to request
       │
       ▼
Proceed to route handler
       │
       ▼
If invalid/expired → return 401 Unauthorized
2.4 Logout Flow
text
User clicks logout
       │
       ▼
Node.js deletes session from `sessions` table
       │
       ▼
Clear HTTP-only cookie
       │
       ▼
Redirect to login page
Phase 3: Python Email Notification System
What Python Will Handle
3.1 Email Queue Processor (Background Task)
Create a new Python script email_worker.py that runs continuously or as a scheduled task:

text
Every 5 minutes:
       │
       ▼
Connect to Node.js SQLite database (same vendors.db file)
       │
       ▼
SELECT * FROM email_queue WHERE status = 'pending'
       │
       ▼
For each email:
       │
       ├─→ Send email via SMTP (Gmail/163/etc.)
       │
       ├─→ On success: UPDATE email_queue SET status = 'sent', sent_at = NOW()
       │
       └─→ On failure: UPDATE email_queue SET status = 'failed', retry_count + 1
       │
       ▼
Log results to console/file
3.2 Email Types to Implement
Email Type	Trigger	Sent By
Welcome / Verification	User registration	Python (via queue)
Password Reset Request	User clicks "Forgot Password"	Python (via queue)
Risk Alert - New Vendor	High-risk vendor added	Python (via queue)
Risk Alert - Score Change	Vendor risk score increases significantly	Python (via queue)
Weekly/Monthly Digest	Scheduled (cron job)	Python (direct)
3.3 Risk Alert Notification Flow
text
Python backend analyzes a vendor (via /analyze endpoint)
       │
       ▼
If risk_score > threshold (e.g., 70 for High Risk):
       │
       ├─→ Insert alert into risk_alerts table (same as before)
       │
       └─→ Also insert into email_queue for subscribed users
       │
       ▼
For each user subscribed to this vendor:
       │
       ├─→ Check user_preferences for alert settings
       │
       ├─→ Generate personalized email content
       │
       └─→ Insert into email_queue
       │
       ▼
email_worker.py sends emails in background
3.4 Password Reset Flow
text
User requests password reset
       │
       ▼
Node.js creates password reset token (expires in 1 hour)
       │
       ▼
Node.js inserts email into email_queue with reset link
       │
       ▼
Python sends email with link: https://yourapp.com/reset?token=...
       │
       ▼
User clicks link → Node.js validates token
       │
       ▼
Node.js presents password reset form
       │
       ▼
User submits new password → Node.js updates password_hash
       │
       ▼
Node.js invalidates all existing sessions for this user
Phase 4: Integration Between Node.js and Python
How They Will Communicate
Direction	Method	Purpose
Frontend → Node.js	HTTP (REST)	All user-facing operations
Frontend → Python	HTTP (REST)	Risk analysis requests
Node.js → Python	Not needed	Node.js only writes to email_queue
Python → Node.js	Direct SQLite access	Read email_queue, write sent status
Python → Database	SQLite connection	Read/write to same vendors.db file
Shared Database Access Configuration
Both Node.js and Python must use the same file path for vendors.db:

text
Project Root/
├── BACKENDD/
│   ├── server.js         (Node.js)
│   └── database/
│       └── vendors.db    ← SHARED FILE
│
└── Python_BackEnd/
    ├── app.py            (Python)
    ├── email_worker.py   (Python)
    └── (access same vendors.db via relative path ../BACKENDD/database/vendors.db)
Important: SQLite supports concurrent reads, but writes need handling. Use WAL mode:

sql
PRAGMA journal_mode=WAL;
Phase 5: API Endpoints to Implement
Node.js (Authentication Endpoints)
Method	Endpoint	Purpose	Authentication
POST	/auth/register	Create new user account	None
POST	/auth/login	Login and create session	None
POST	/auth/logout	Destroy current session	Required
GET	/auth/me	Get current user info	Required
POST	/auth/forgot-password	Request password reset email	None
POST	/auth/reset-password	Reset password with token	None
GET	/auth/verify/:token	Verify email address	None
PUT	/auth/profile	Update user profile	Required
POST	/auth/change-password	Change password	Required
Node.js (User Preference Endpoints)
Method	Endpoint	Purpose
GET	/user/preferences	Get notification settings
PUT	/user/preferences	Update notification settings
GET	/user/subscriptions	Get vendors user follows
POST	/user/subscriptions/:vendorId	Subscribe to vendor alerts
DELETE	/user/subscriptions/:vendorId	Unsubscribe from vendor
Node.js (Vendor Operations - Keep Existing)
Method	Endpoint	Purpose
POST	/api/vendors	Save analysis results
GET	/api/vendors	Get all vendors
DELETE	/api/vendors/:id	Delete vendor
GET	/api/alerts	Get risk alerts
PUT	/api/alerts/:id/read	Mark alert as read
Python (Risk Analysis - Keep Existing)
Method	Endpoint	Purpose
GET	/analyze?vendor=...	Full Six Pillar analysis
GET	/health	Health check
Phase 6: Implementation Order (Step by Step)
Week 1: Database + Node.js Authentication
Expand database schema - Add users, sessions, email_queue tables

Add bcrypt dependency - For password hashing

Implement register endpoint - With email queue insertion

Implement login endpoint - With session creation

Add session middleware - To protect existing vendor routes

Implement logout endpoint - Session cleanup

Test authentication flow - Using Postman or frontend

Week 2: Email Infrastructure (Python)
Create email_worker.py - Background queue processor

Configure SMTP settings - In .env file (Gmail/163/etc.)

Implement verification email template - HTML + plain text

Implement password reset email template

Schedule email_worker to run every 5 minutes - Using cron or a loop

Test email sending - Verify emails arrive

Week 3: Risk Alert Emails
Modify Python /analyze endpoint - To trigger alerts on high risk scores

Create user_preferences table - Store notification settings

Create alert_subscriptions table - Link users to vendors

Implement subscription endpoints - In Node.js

Modify Python to check subscriptions - Before inserting into email_queue

Create alert email templates - For different severity levels

Week 4: Polish & Security
Add rate limiting - On auth endpoints (prevent brute force)

Add input validation - Sanitize all user inputs

Implement request logging - For audit trails

Add session cleanup job - Remove expired sessions daily

Create user dashboard - To manage preferences and view alerts

Test complete flow - End-to-end testing

Phase 7: Directory Structure After Implementation
text
Project Root/
│
├── BACKENDD/
│   ├── server.js                    (Node.js - Auth + Vendor DB)
│   ├── middleware/
│   │   ├── auth.js                  (Session validation)
│   │   └── rateLimit.js             (Rate limiting)
│   ├── routes/
│   │   ├── auth.js                  (Register, login, logout)
│   │   ├── users.js                 (Profile, preferences)
│   │   ├── vendors.js               (CRUD operations)
│   │   └── alerts.js                (Alert management)
│   ├── database/
│   │   └── vendors.db               (All tables: users, sessions, vendors, etc.)
│   └── package.json
│
├── Python_BackEnd/
│   ├── app.py                       (Risk analysis - unchanged)
│   ├── email_worker.py              (NEW - Background email processor)
│   ├── email_templates/
│   │   ├── verify_email.html
│   │   ├── reset_password.html
│   │   ├── risk_alert.html
│   │   └── weekly_digest.html
│   ├── logic/
│   │   └── (all existing modules - unchanged)
│   └── requirements.txt
│
└── FrontEnd/
    ├── login.html                   (NEW)
    ├── register.html                (NEW)
    ├── profile.html                 (NEW)
    ├── (existing pages - update to check auth)
    └── ...
Phase 8: Security Considerations
Concern	Solution
Password storage	bcrypt with salt (cost factor 12+)
Session hijacking	HTTP-only cookies, regenerate on login
Brute force attacks	Rate limiting: 5 attempts per 15 minutes
SQL injection	Parameterized queries only
Email spoofing	DKIM/SPF records for sending domain
Token expiration	Reset tokens expire in 1 hour
Session fixation	Regenerate session ID on login
XSS attacks	Escape all user-generated content
Phase 9: Communication Between Services
Option A: Shared Database (Recommended)
python
# Python reads from email_queue
import sqlite3
conn = sqlite3.connect('../BACKENDD/database/vendors.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM email_queue WHERE status = 'pending'")
Option B: HTTP API (Alternative)
Node.js exposes an endpoint for Python to get pending emails:

text
GET /internal/email-queue (Node.js)
POST /internal/email-status (Node.js)
Python calls these endpoints instead of direct DB access.

Option C: Redis Queue (Advanced)
Use Redis as a message broker between Node.js and Python. Better for high scale, but adds complexity.

Summary of Responsibilities
Service	Responsibilities
Node.js (Port 5001)	User auth, sessions, vendor CRUD, alert storage, user preferences, request validation, rate limiting
Python (Port 5000)	Risk analysis (Six Pillars), email_queue reading, SMTP sending, alert triggering
SQLite Database	Stores users, sessions, vendors, history, alerts, email_queue, preferences
Frontend	Login/register forms, protected routes, API calls to both backends
Next Actions for You
Decide on session storage - In-memory (simple) vs database (persistent across restarts)

Set up SMTP credentials - Create a dedicated email account for notifications

Design email templates - HTML templates for verification, reset, and alerts

Start with Week 1 tasks - Database schema and basic authentication

Test each component individually before integrating