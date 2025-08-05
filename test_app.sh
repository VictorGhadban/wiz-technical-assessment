#!/bin/bash
# scripts/test_vulnerabilities.sh - Test the intentional vulnerabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

print_vulnerability() {
    echo -e "${RED}[VULNERABILITY CONFIRMED]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Load infrastructure outputs
if [ ! -f infrastructure_outputs.json ]; then
    echo "infrastructure_outputs.json not found. Run deployment first."
    exit 1
fi

DB_PUBLIC_IP=$(jq -r '.database_public_ip.value' infrastructure_outputs.json)
S3_BUCKET=$(jq -r '.s3_bucket_name.value' infrastructure_outputs.json)
S3_URL=$(jq -r '.s3_bucket_url.value' infrastructure_outputs.json)

echo -e "${BLUE}=== Wiz Technical Exercise - Vulnerability Testing ===${NC}"
echo

# Test 1: SSH Access to Database
test_ssh_access() {
    print_status "Testing SSH access to database server..."
    
    # Test if port 22 is open
    if nc -z -v -w5 $DB_PUBLIC_IP 22 2>/dev/null; then
        print_vulnerability "SSH port 22 is accessible from internet"
        print_info "Command: ssh -i ~/.ssh/id_rsa ec2-user@$DB_PUBLIC_IP"
    else
        echo "SSH port not accessible (might still be starting up)"
    fi
    echo
}

# Test 2: S3 Bucket Public Access
test_s3_public_access() {
    print_status "Testing S3 bucket public access..."
    
    # Try to list bucket contents without authentication
    if curl -s "$S3_URL/" | grep -q "ListBucketResult"; then
        print_vulnerability "S3 bucket allows public listing"
        print_info "URL: $S3_URL/"
        
        # Try to access specific files
        echo "Available files in bucket:"
        curl -s "$S3_URL/" | grep -o '<Key>[^<]*</Key>' | sed 's/<Key>//g' | sed 's|</Key>||g' | head -5
    else
        echo "S3 bucket access test failed"
    fi
    echo
}

# Test 3: Database Connection
test_database_connection() {
    print_status "Testing database connection vulnerabilities..."
    
    # Test if MongoDB port is accessible from VPC
    print_info "MongoDB should be accessible from Kubernetes pods but not from internet"
    print_info "Connection string: mongodb://taskuser:password123@$DB_PUBLIC_IP:27017/taskdb"
    echo
}

# Test 4: Container Vulnerabilities
test_container_vulnerabilities() {
    print_status "Testing container security issues..."
    
    # Check if containers are running with elevated privileges
    PRIVILEGED_PODS=$(kubectl get pods -l app=wiz-task-app -o jsonpath='{.items[*].spec.containers[*].securityContext.privileged}' 2>/dev/null || echo "")
    
    if [[ "$PRIVILEGED_PODS" == *"true"* ]]; then
        print_vulnerability "Containers running with privileged access"
    fi
    
    # Check service account permissions
    SA_NAME=$(kubectl get pods -l app=wiz-task-app -o jsonpath='{.items[0].spec.serviceAccountName}' 2>/dev/null || echo "")
    if [[ "$SA_NAME" == "cluster-admin-sa" ]]; then
        print_vulnerability "Pods using cluster-admin service account"
    fi
    
    # Check for host mounts
    HOST_MOUNTS=$(kubectl get pods -l app=wiz-task-app -o jsonpath='{.items[*].spec.volumes[*].hostPath}' 2>/dev/null || echo "")
    if [[ -n "$HOST_MOUNTS" ]]; then
        print_vulnerability "Host filesystem mounted in containers"
    fi
    
    echo
}

# Test 5: Network Security
test_network_security() {
    print_status "Testing network security configuration..."
    
    # Check if application is publicly accessible
    LB_HOSTNAME=$(kubectl get service wiz-task-app-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")
    
    if [[ -n "$LB_HOSTNAME" && "$LB_HOSTNAME" != "null" ]]; then
        print_info "Application LoadBalancer: http://$LB_HOSTNAME"
        
        # Test if application responds
        if curl -s -o /dev/null -w "%{http_code}" "http://$LB_HOSTNAME/health" | grep -q "200"; then
            print_vulnerability "Application publicly accessible without authentication"
        fi
        
        # Test debug endpoint
        if curl -s "http://$LB_HOSTNAME/debug/info" | grep -q "environment"; then
            print_vulnerability "Debug endpoint exposing sensitive information"
            print_info "Debug URL: http://$LB_HOSTNAME/debug/info"
        fi
    else
        print_info "LoadBalancer still provisioning..."
    fi
    echo
}

# Test 6: IAM Permissions
test_iam_permissions() {
    print_status "Testing IAM permission issues..."
    
    print_vulnerability "Database instance has overly permissive IAM role"
    print_info "Instance can access S3, EC2, and IAM with full permissions"
    echo
}

# Test 7: Backup Security
test_backup_security() {
    print_status "Testing backup security..."
    
    # Check if backups contain sensitive data
    print_vulnerability "Database backups contain sensitive credentials"
    print_vulnerability "Backups stored in publicly readable S3 bucket"
    print_info "Check: $S3_URL/db_credentials_*.txt"
    echo
}

# AWS Security Tools Integration
test_aws_security_tools() {
    print_status "Testing AWS security tool detection..."
    
    # GuardDuty findings
    print_info "GuardDuty should detect:"
    echo "  - Cryptocurrency mining activity simulation"
    echo "  - Unusual API calls from compromised instances"
    echo "  - Communication with known malicious IPs"
    
    # Config compliance
    print_info "AWS Config should flag:"
    echo "  - S3 buckets with public read access"
    echo "  - Security groups allowing 0.0.0.0/0 SSH access"
    echo "  - Root access device usage"
    
    # CloudTrail events
    print_info "CloudTrail should log:"
    echo "  - All API calls and resource access"
    echo "  - Administrative actions"
    echo "  - Data access patterns"
    
    echo
}

# Generate test report
generate_test_report() {
    print_status "Generating vulnerability test report..."
    
    cat > vulnerability_test_report.md << 'EOF'
# Wiz Technical Exercise - Vulnerability Test Report

## Executive Summary
This report documents the intentional security vulnerabilities implemented in the test environment and their potential impact.

## Identified Vulnerabilities

### 1. Infrastructure Layer
- **Outdated Operating System**: Database VM running outdated Amazon Linux 2
- **Outdated Database**: MongoDB 4.4.18 with known security vulnerabilities
- **Insecure Network Configuration**: SSH access allowed from 0.0.0.0/0
- **Overly Permissive IAM**: Database instance with broad S3, EC2, and IAM permissions

### 2. Data Storage
- **Public S3 Bucket**: Database backups accessible without authentication
- **Exposed Credentials**: Plain text credentials stored in publicly accessible files
- **Insufficient Encryption**: Data at rest not properly encrypted

### 3. Container Security
- **Privileged Containers**: Applications running with root privileges
- **Host Access**: Container can access host filesystem and Docker daemon
- **Excessive Permissions**: Cluster-admin service account privileges

### 4. Application Security
- **Debug Endpoints**: Sensitive system information exposed via /debug/info
- **
