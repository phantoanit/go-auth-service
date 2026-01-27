#!/bin/bash
set -e

REPO_NAME=$1
REPO_TYPE=$2  # shared-library, microservice, infrastructure, devtools

if [ -z "$REPO_NAME" ] || [ -z "$REPO_TYPE" ]; then
    echo "Usage: ./setup-cicd.sh <repo-name> <repo-type>"
    echo "Types: shared-library, microservice, infrastructure, devtools"
    exit 1
fi

echo "🔧 Setting up CI/CD for $REPO_NAME ($REPO_TYPE)"

# Create .github/workflows directory
mkdir -p .github/workflows

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TEMPLATE_DIR="$SCRIPT_DIR/../"

# Copy appropriate templates
case $REPO_TYPE in
    "shared-library")
        echo "📋 Copying shared library templates..."
        cp "$TEMPLATE_DIR/shared-library/ci.yml" .github/workflows/
        cp "$TEMPLATE_DIR/shared-library/release.yml" .github/workflows/
        ;;
    "microservice")
        echo "📋 Copying microservice templates..."
        cp "$TEMPLATE_DIR/microservices-template/ci.yml" .github/workflows/
        cp "$TEMPLATE_DIR/microservices-template/release.yml" .github/workflows/
        cp "$TEMPLATE_DIR/microservices-template/deploy-dev.yml" .github/workflows/
        cp "$TEMPLATE_DIR/microservices-template/deploy-staging.yml" .github/workflows/
        cp "$TEMPLATE_DIR/microservices-template/deploy-production.yml" .github/workflows/
        ;;
    "infrastructure")
        echo "📋 Copying infrastructure templates..."
        cp "$TEMPLATE_DIR/infrastructure/validate.yml" .github/workflows/
        ;;
    "devtools")
        echo "📋 Copying devtools templates..."
        cp "$TEMPLATE_DIR/devtools/ci.yml" .github/workflows/
        ;;
    *)
        echo "❌ Unknown repo type: $REPO_TYPE"
        exit 1
        ;;
esac

# Copy dependabot config
echo "📋 Copying Dependabot configuration..."
mkdir -p .github
cp "$TEMPLATE_DIR/dependabot/dependabot.yml" .github/

echo ""
echo "✅ CI/CD setup complete for $REPO_NAME"
echo ""
echo "📝 Next steps:"
echo "1. Review the generated workflows in .github/workflows/"
echo "2. Configure required secrets in GitHub repo settings:"
echo "   - KUBECONFIG_DEV (for development deployments)"
echo "   - KUBECONFIG_STAGING (for staging deployments)"
echo "   - KUBECONFIG_PROD (for production deployments)"
echo "   - SLACK_WEBHOOK (optional, for notifications)"
echo "   - SNYK_TOKEN (optional, for security scanning)"
echo "3. Customize workflow files as needed for your service"
echo "4. Commit and push changes to your repository"
echo ""
echo "📚 For more information, see:"
echo "   - docs/cicd/CICD_GUIDE.md"
echo "   - docs/cicd/SECRETS_SETUP.md"
echo "   - docs/cicd/DEPLOYMENT_GUIDE.md"
