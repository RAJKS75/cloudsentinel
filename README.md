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

Check deployment in portal
Or check your GitHub repo → Actions tab

# Test the URL
curl -I https://your-app.azurestaticapps.net

# Alternative: Azure CLI for Method 1
 Install Azure CLI if not present
 macOS: brew install azure-cli
 Windows: winget install Microsoft.AzureCLI
 Linux: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

Login
 az login

# Install Azure CLI if not present
# macOS: brew install azure-cli
# Windows: winget install Microsoft.AzureCLI
# Linux: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login
az login

# Create resource group
az group create \
  --name rg-cloudsentinel \
  --location eastus

# Create Static Web App
az staticwebapp create \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --source https://github.com/YOUR_USERNAME/cloudsentinel \
  --branch main \
  --location eastus \
  --sku Free \
  --app-location "/" \
  --output-location "/"

# Get the URL
az staticwebapp show \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --query "defaultHostname" \
  --output tsv

# Method 2: Azure App Service (Traditional Web App)
Why this one: You need custom VNet integration, app settings, or your organization requires App Service.

Step 1: Create Web App
 az login

# Create resource group
az group create --name rg-cloudsentinel --location eastus

# Create App Service plan (B1 = Basic, ~$13/month)
# Use F1 (Free) for testing
az appservice plan create \
  --name asp-cloudsentinel \
  --resource-group rg-cloudsentinel \
  --sku B1 \
  --is-linux

# Create Web App
az webapp create \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --plan asp-cloudsentinel \
  --runtime "NODE:18-LTS"

# Get URL
az webapp show \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --query "defaultHostName" \
  --output tsv

# Step 2: Deploy Files

 # Deploy using ZIP
cd cloudsentinel
zip -r ../cloudsentinel-deploy.zip .

az webapp deployment source config-zip \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --src ../cloudsentinel-deploy.zip