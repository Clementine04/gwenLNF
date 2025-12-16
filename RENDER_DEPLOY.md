# ISU Lost n Found - Render Deployment

## Automatic Deployment (render.yaml)

This project includes a `render.yaml` file for automatic service configuration on Render.

## Manual Deployment Steps

If you prefer manual setup:

### 1. Create a New Web Service on Render

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click **New +** → **Web Service**
3. Connect your GitHub/GitLab repository

### 2. Configure the Service

| Setting | Value |
|---------|-------|
| **Name** | `isu-lost-n-found` |
| **Runtime** | Python 3 |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `gunicorn app:app` |

### 3. Set Environment Variables

In the Render dashboard, add these environment variables:

| Variable | Value | Notes |
|----------|-------|-------|
| `SECRET_KEY` | (generate a random string) | Use `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URI` | `sqlite:///lostnfound.db` | For SQLite (default) |
| `PYTHON_VERSION` | `3.11.0` | Optional |

### 4. Deploy

Click **Create Web Service** and Render will:
1. Install dependencies from `requirements.txt`
2. Start the app with Gunicorn

## Important Notes

- **File Uploads**: With SQLite, uploaded files are stored on the ephemeral filesystem and will be lost on redeploy. For production, consider using a cloud storage service like AWS S3 or Cloudinary.
- **Database**: SQLite works for small deployments. For larger scale, consider PostgreSQL (Render offers managed PostgreSQL).

## Admin Access

Default admin credentials:
- **Email**: `admin@isu.edu`
- **Password**: `admin123`

⚠️ **Change the admin password after deployment!**
