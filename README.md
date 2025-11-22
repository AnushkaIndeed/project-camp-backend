Project Camp – Backend API

A complete authentication and user management backend built using Node.js, Express, Mongoose & JWT.


This backend supports:

User registration & login

Email verification

Access + Refresh token authentication

Logout

Forgot password & Reset password

Resend verification email

Current user endpoint

Secure cookies

Validation & error handling

🚀 Tech Stack

Node.js

Express.js

MongoDB + Mongoose

JWT Authentication

Mailgen + Nodemailer

bcrypt

Cookie-parser

📁 Project Structure
src/
│
├── controllers/
│   └── auth.controllers.js
│
├── middlewares/
│   ├── auth.middleware.js
│   └── validate.middleware.js
│
├── models/
│   └── user.models.js
│
├── routes/
│   └── auth.routes.js
│
├── utils/
│   ├── api-error.js
│   ├── api-response.js
│   ├── async-handler.js
│   ├── mail.js
│
├── app.js
└── server.js

🔧 Setup Instructions
1. Clone the repo
git clone https://github.com/your-username/project-camp-backend.git
cd project-camp-backend

2. Install dependencies
npm install

3. Setup environment variables
cp .env.example .env


Fill .env with your actual credentials.

4. Run the server
npm run dev


OR

node server.js

🔐 Authentication Flow
✔ Register User
✔ Login User
✔ Verify Email
✔ Refresh Token
✔ Get Current User
✔ Logout
✔ Forgot Password
✔ Reset Password

Every protected route uses verifyJWT middleware.

📮 API Endpoints (Auth)
Method	Endpoint	Description
POST	/api/v1/auth/register	Register user + send verification email
POST	/api/v1/auth/login	Login & receive tokens
POST	/api/v1/auth/logout	Logout user
GET	/api/v1/auth/current-user	Get logged-in user
GET	/api/v1/auth/verify-email/:token	Verify email
POST	/api/v1/auth/resend-verification	Resend verification email
POST	/api/v1/auth/refresh-token	Refresh access token
POST	/api/v1/auth/forgot-password	Request password reset
POST	/api/v1/auth/reset-password/:resetToken	Reset password

📌 License
This project is open-sourced under the MIT License.

✅ 4. Commit Message (use this on first push)
feat: initial backend setup with authentication, JWT, email verification, password reset, middleware, and us
