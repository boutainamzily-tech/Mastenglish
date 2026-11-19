# Mastenglish

An Arabic, right-to-left website for online English lessons for
children, teenagers, and adults.

## Features

- Student registration and login
- Password recovery by email when SMTP is configured
- Free trial booking requests and administrator approval
- Study groups and student enrollment
- Scheduled 40-minute lessons
- Student booking and lesson schedule pages
- Administrator-managed monthly subscription access
- Zoom Meeting SDK integration with server-side access checks
- Responsive pages for desktop and mobile

## Project status

The project is under development and has been tested locally.

A PayPal card payment link has been tested successfully.
The final subscription payment links are not integrated yet.
Subscription activation is currently managed manually by the administrator.

The homepage offers 3 lessons per week.
Some backend settings still use the previous limit of 8 lessons per month
and the previous prices in MAD. These settings need to be updated.

## Technologies

HTML, CSS, JavaScript, Node.js, Express, SQLite,
bcryptjs, JSON Web Tokens, Nodemailer, Luxon, and Zoom Meeting SDK.

## Folder structure

- `boutaina work/`: frontend pages and media
- `server/`: Express backend and database setup
- `server/.env.example`: configuration template
- `.gitignore`: files excluded from Git

## Local setup

Install Node.js and npm.

From the project folder:

    cd server
    npm ci

Copy `.env.example` to `.env`:

    cp .env.example .env

Generate an authentication secret:

    node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"

Set `AUTH_SECRET` in `.env` to the generated value.

Configure these Zoom values before starting:

- `ZOOM_CLIENT_ID`
- `ZOOM_CLIENT_SECRET`
- `ZOOM_MEETING_ID`
- `ZOOM_MEETING_PASSWORD`

Email features require `SMTP_USER` and `SMTP_PASS`.
For the current Gmail transport, use a Gmail app password.

Start the server:

    npm start

Open:

    http://127.0.0.1:3000

The database tables are initialized when the server starts.

## Administrator setup

First register an account through the website.

Then, from the `server` folder, run:

    node make-admin.js your-email@example.com

This command grants administrator access to that account
and removes administrator access from other accounts.

## Security and private data

Real environment files, database files, and dependency folders
must not be committed.

Use your own configuration and test accounts.
Do not include real student data in the repository.

## Deployment

This project requires a Node.js server and persistent database storage.
GitHub Pages alone cannot run the backend.

Production deployment and final payment integration are still pending.