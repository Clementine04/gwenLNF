# ISU Lost n Found

A web-based information system where ISU Cauayan students & staff can report lost or found items on campus, search for matching items, and claim items through a simple verification workflow.

## Features

- Report lost or found items
- Browse and search for items
- Claim found items
- Admin dashboard for managing reports and claims
- Statistics for administrators

## Installation

1. Clone this repository
2. Create a virtual environment and activate it:
   ```
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # Linux/Mac
   ```
3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Running the Application

1. Start the Flask development server:
   ```
   python app.py
   ```
2. Open your web browser and go to `http://localhost:5000`

## Default Admin Account

The application automatically creates an admin account if no users exist in the database:
- Email: admin@isu.edu
- Password: admin123

## User Roles

- **Guest**: Can browse lost/found listings (read-only)
- **User**: Can create new "lost" or "found" posts, edit or withdraw own posts
- **Admin**: Can approve/reject posts, manage claim requests, view statistics 