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

# Step 3: Configure Startup Command

 By default, App Service looks for a Node.js server. Since this is a static site, override it:
 az webapp config set \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --startup-file "npx serve -s . -l 8080"

By default, App Service looks for a Node.js server. Since this is a static site, override it:
az webapp config set \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --startup-file "npx serve -s . -l 8080"

  Or set via portal: Configuration → General Settings → Startup Command → npx serve -s . -l 8080

# Step 4: Enable HTTPS (Auto-enabled on App Service)
App Service provides a *.azurewebsites.net SSL cert automatically. For custom domains:
# Add custom domain (you need DNS control first)
az webapp config hostname add \
  --webapp-name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --hostname scans.yourdomain.com

# Bind managed certificate
az webapp config ssl create \
  --name cloudsentinel-cspm-ssl \
  --resource-group rg-cloudsentinel \
  --webapp-name cloudsentinel-cspm \
  --hostname scans.yourdomain.com

# Method 3: Azure Blob Storage Static Website (Cheapest)
Why this one: Literally ~$0.02/month. No compute. Good for internal tools with low traffic.
# Create storage account
az storage account create \
  --name cloudsentinelsa \
  --resource-group rg-cloudsentinel \
  --location eastus \
  --sku Standard_LRS \
  --kind StorageV2

# Enable static website
az storage blob service-properties update \
  --account-name cloudsentinelsa \
  --static-website \
  --index-document index.html \
  --404-document index.html

# Get the static website URL
az storage account show \
  --name cloudsentinelsa \
  --resource-group rg-cloudsentinel \
  --query "primaryEndpoints.web" \
  --output tsv
# Returns: https://cloudsentinelsa.z5.web.core.windows.net/

# Upload files
az storage blob upload-batch \
  --destination '$web' \
  --source ./cloudsentinel/ \
  --account-name cloudsentinelsa \
  --overwrite

Note: Blob static sites don't get automatic HTTPS on the z5.web.core.windows.net URL. You need Azure CDN or a custom domain with Front Door for HTTPS.

# Custom Domain Setup (Any Method)
DNS Configuration
Add these records at your domain registrar:
| Type  | Name    | Value                                      |
|-------|---------|--------------------------------------------|
| CNAME | `scans` | `cloudsentinel-cspm.azurestaticapps.net`   |
| TXT   | `asuid.scans` | (get from Azure portal → Custom domains) |

In Azure Portal
Go to your Static Web App / Web App
Custom domains → Add
Enter scans.yourdomain.com
Azure will validate DNS → click Create
SSL auto-provisions (free on Static Web Apps)

# Quick-Start Cheat Sheet (Method 1, All CLI)
# 1. Create repo and push
cd cloudsentinel && git init && git add . && git commit -m "init"
gh repo create cloudsentinel --public --push --source=.

# 2. One command to deploy
az login
az group create --name rg-cloudsentinel --location eastus
az staticwebapp create \
  --name cloudsentinel-cspm \
  --resource-group rg-cloudsentinel \
  --source https://github.com/YOUR_USER/cloudsentinel \
  --branch main \
  --sku Free \
  --app-location "/" \
  --output-location "/"

# 3. Get URL
az staticwebapp show -n cloudsentinel-cspm -g rg-cloudsentinel \
  --query defaultHostname -o tsv

  That's it. Three commands, zero cost, globally distributed, HTTPS enabled.