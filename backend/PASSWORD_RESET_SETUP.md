# Password Reset via Email Setup Guide

## 🚀 What I've Done

I've completely set up password reset functionality for your BidVerse project. Here's everything that's ready:

### ✅ Completed Setup:
1. **Environment Variables**: Created `env_example.txt` with required variables
2. **Django Settings**: Updated to load `.env` file and configured email settings
3. **Email Templates**: Created beautiful HTML and text email templates
4. **Test Script**: Comprehensive testing tool for email and password reset
5. **Dependencies**: `python-dotenv` already in requirements.txt

### 🔧 What You Need to Do

## Step 1: Set Up Gmail App Password

**IMPORTANT**: Gmail requires an "App Password" for SMTP access, not your regular password.

### How to Get Gmail App Password:

1. **Go to Google Account Settings**:
   - Visit: https://myaccount.google.com/
   - Sign in to your Gmail account

2. **Enable 2-Factor Authentication** (if not already enabled):
   - Go to "Security" in the left sidebar
   - Under "Signing in to Google", click "2-Step Verification"
   - Follow the steps to enable 2FA

3. **Generate App Password**:
   - Still in "Security" section
   - Scroll down to "App passwords"
   - Click "App passwords"
   - Select "Mail" and "Other (custom name)"
   - Enter "BidVerse" as the name
   - Click "Generate"

4. **Copy the 16-character password** (ignore spaces):
   - Example: `abcd-efgh-ijkl-mnop`

## Step 2: Create .env File

Create a file named `.env` in your `backend` directory:

```bash
# Copy the contents from env_example.txt and replace with your real values
EMAIL_HOST_USER=your-actual-gmail@gmail.com
EMAIL_HOST_PASSWORD=your-16-char-app-password
```

**Example .env file:**
```bash
EMAIL_HOST_USER=johnsmith@gmail.com
EMAIL_HOST_PASSWORD=abcd-efgh-ijkl-mnop
```

## Step 3: Test Email Configuration

Run the test script to verify everything works:

```bash
cd backend
python test_email.py
```

This will test:
- Email connection to Gmail SMTP
- Sending a test email
- Password reset token generation
- Password reset email sending

## Step 4: Start Your Server

```bash
cd backend
python manage.py runserver
```

## Step 5: Test Password Reset

### Option A: Web Interface
Visit: `http://localhost:8000/forgot-password/`

### Option B: API Endpoints

**Request Password Reset:**
```bash
curl -X POST http://localhost:8000/api/auth/password-reset-request/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**Reset Password:**
```bash
curl -X POST http://localhost:8000/api/auth/password-reset-confirm/uidb64/token/ \
  -H "Content-Type: application/json" \
  -d '{"password": "newpassword123"}'
```

## 📧 Email Templates Created

- `templates/registration/password_reset_email.html` - Beautiful HTML email
- `templates/registration/password_reset_email.txt` - Plain text fallback
- `templates/registration/password_reset_subject.txt` - Email subject

## 🔒 Security Features

- ✅ Password reset links expire in 3 days (configurable)
- ✅ Cryptographically secure tokens
- ✅ HTTPS recommended for production
- ✅ User verification before sending reset email

## 🐛 Troubleshooting

### If Email Connection Fails:
1. Double-check your Gmail credentials in `.env`
2. Ensure you're using an App Password, not your regular password
3. Verify 2FA is enabled on your Google account

### If Emails Go to Spam:
1. Check your Gmail's "Spam" folder
2. Add BidVerse emails to your contacts
3. Consider using a dedicated email service like SendGrid for production

### Common Issues:
- **535 Authentication Error**: Wrong App Password
- **Connection Timeout**: Check internet connection
- **Template Not Found**: Ensure templates are in correct directory

## 🚀 Production Deployment

For production, consider:

1. **Use a dedicated email service** (SendGrid, Mailgun, Amazon SES)
2. **Enable HTTPS** for secure password reset
3. **Add rate limiting** to prevent abuse
4. **Use environment-specific settings**

## 📞 Support

If you encounter issues:
1. Run `python test_email.py` and share the output
2. Check Django logs for detailed error messages
3. Verify your `.env` file contents (don't share passwords!)

---

**Your password reset system is now fully configured!** 🎉

Just set up your Gmail App Password and create the `.env` file, and you'll have working password reset via email.
