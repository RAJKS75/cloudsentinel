# cloudsentinel

# Method 1: Azure Static Web Apps (Recommended)
Why this one: Free tier, automatic HTTPS, global CDN, GitHub Actions CI/CD built in, $0/month for personal use.

## Step 1: Push to GitHub

cd cloudsentinel

# Initialize git
git init
git add .
git commit -m "Initial commit: CloudSentinel CSPM tool"

# Create a repo on GitHub first, then:
git remote add origin https://github.com/YOUR_USERNAME/cloudsentinel.git
git branch -M main
git push -u origin main

# Step 2: Create Static Web App via Azure Portal

    Go to portal.azure.com
    Search for "Static Web Apps" → Create
    Fill in:
    Subscription: Your subscription
    Resource Group: Create new → rg-cloudsentinel
    Name: cloudsentinel-cspm
    Region: Closest to you (e.g., East US)
    Plan type: Free (includes 100GB bandwidth/month)
    Deployment source: GitHub
    GitHub account: Connect your account
    Repository: Select cloudsentinel
    Branch: main
    Build preset: Custom
    App location: /
    API location: (leave empty)
    Output location: /
Click Review + Create → Create

# Step 3: Wait for Deployment

Azure will automatically:

Create a GitHub Actions workflow in .github/workflows/
Build and deploy your site
Provide a URL like: https://gentle-plant-0a1b2c3d.azurestaticapps.net

# Step 4: Verify

# Check deployment in portal
# Or check your GitHub repo → Actions tab

# Test the URL
curl -I https://your-app.azurestaticapps.net