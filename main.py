import os
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI, Cookie, Response, HTMLResponse
from fastapi.responses import RedirectResponse
import httpx
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

app = FastAPI()

# Environment Variables
PORT = int(os.getenv("PORT", 3000))
META_APP_ID = os.getenv("META_APP_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET")
META_REDIRECT_URI = os.getenv("META_REDIRECT_URI", "http://meta-app-production-2ada07e7.up.railway.app/auth/facebook/callback")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Initialize Supabase Client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
GRAPH_API_VERSION = "v26.0"

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <div style="font-family: sans-serif; padding: 3rem; text-align: center;">
      <h1>FastAPI Meta OAuth & Supabase</h1>
      <p>Secure login with long-lived token persistence.</p>
      <br>
      <a href="/auth/facebook" style="
        display: inline-block;
        padding: 12px 24px;
        background: #1877F2;
        color: white;
        text-decoration: none;
        border-radius: 6px;
        font-weight: bold;
      ">Continue with Facebook</a>
    </div>
    """

@app.get("/auth/facebook")
async def facebook_login(response: Response):
    # Generate unique state token to prevent CSRF attacks
    state = secrets.token_hex(16)
    
    # Securely store state in an HTTP-only cookie (10 min expiry)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=True,  # Set to True in production over HTTPS
        samesite="lax",
        max_age=600
    )
    
    # Build Meta OAuth dialog URL
    auth_url = (
        f"https://www.facebook.com/{GRAPH_API_VERSION}/dialog/oauth"
        f"?client_id={META_APP_ID}"
        f"&redirect_uri={META_REDIRECT_URI}"
        f"&state={state}"
        f"&scope=public_profile,email"
    )
    
    return RedirectResponse(url=auth_url)

@app.get("/auth/facebook/callback", response_class=HTMLResponse)
async def facebook_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    oauth_state: str | None = Cookie(None)
):
    # 1. Handle user cancellation or Graph errors
    if error:
        return f"""
        <h3>Login Cancelled</h3>
        <p><strong>Error:</strong> {error}</p>
        <p>{error_description or 'User denied permissions.'}</p>
        <a href="/">Home</a>
        """
    
    # 2. Validate CSRF state token
    if not state or not oauth_state or state != oauth_state:
        return HTMLResponse(content="<h3>Security Error</h3><p>Invalid state parameter. Potential CSRF attack.</p>", status_code=403)
    
    if not code:
        return HTMLResponse(content="<h3>Error</h3><p>Authorization code missing from response.</p>", status_code=400)
    
    async with httpx.AsyncClient() as client:
        try:
            # 3. Exchange short-lived auth code for a short-lived user access token
            token_url = f"https://graph.facebook.com/{GRAPH_API_VERSION}/oauth/access_token"
            token_res = await client.get(token_url, params={
                "client_id": META_APP_ID,
                "redirect_uri": META_REDIRECT_URI,
                "client_secret": META_APP_SECRET,
                "code": code
            })
            token_data = token_res.json()
            
            if "error" in token_data:
                raise Exception(token_data["error"]["message"])
            
            short_lived_token = token_data["access_token"]
            
            # 4. Exchange short-lived token for a LONG-LIVED access token (~60 days)
            long_token_res = await client.get(token_url, params={
                "grant_type": "fb_exchange_token",
                "client_id": META_APP_ID,
                "client_secret": META_APP_SECRET,
                "fb_exchange_token": short_lived_token
            })
            long_token_data = long_token_res.json()
            
            if "error" in long_token_data:
                raise Exception(long_token_data["error"]["message"])
            
            long_lived_token = long_token_data["access_token"]
            expires_in = long_token_data.get("expires_in", 5183944)  # ~60 days default
            expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
            
            # 5. Fetch user profile fields from Graph API using the long-lived token
            profile_res = await client.get(f"https://graph.facebook.com/{GRAPH_API_VERSION}/me", params={
                "fields": "id,name,email,picture",
                "access_token": long_lived_token
            })
            profile_data = profile_res.json()
            
            if "error" in profile_data:
                raise Exception(profile_data["error"]["message"])
            
            meta_user_id = profile_data["id"]
            name = profile_data.get("name")
            email = profile_data.get("email")
            picture_url = profile_data.get("picture", {}).get("data", {}).get("url")
            
            # 6. Database Persistence: Upsert user record into Supabase PostgreSQL
            user_payload = {
                "meta_user_id": meta_user_id,
                "name": name,
                "email": email,
                "picture_url": picture_url,
                "access_token": long_lived_token,
                "token_expires_at": expires_at.isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            supabase.table("users").upsert(user_payload, on_conflict="meta_user_id").execute()
            
            return f"""
            <div style="font-family: sans-serif; padding: 3rem;">
              <h2 style="color: #2e7d32;">Authentication & Database Sync Successful!</h2>
              <img src="{picture_url or ''}" alt="Avatar" style="border-radius: 50%; width: 80px; height: 80px;" />
              <p><strong>Name:</strong> {name}</p>
              <p><strong>Email:</strong> {email or 'Not provided'}</p>
              <p><strong>Meta User ID:</strong> {meta_user_id}</p>
              <p style="color: #1565c0;"><strong>Database Status:</strong> Long-lived access token persisted in Supabase (Valid for ~60 days).</p>
              <br>
              <a href="/">Home</a>
            </div>
            """
            
        except Exception as e:
            return HTMLResponse(content=f"<h3>Authentication Failed</h3><p>{str(e)}</p>", status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
