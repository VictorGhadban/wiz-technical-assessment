
provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "ec2_backup_role" {
  name = "ec2_backup_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_backup_policy_attach" {
  role       = aws_iam_role.ec2_backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_instance" "mongo_db" {
  ami                         = "ami-04ff98ccbfa41c9ad" # Ubuntu 22.04
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public_subnet.id
  associate_public_ip_address = true
  key_name                    = "wiz-key"
  vpc_security_group_ids      = [aws_security_group.mongo_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install -y gnupg curl awscli cron

              # Add MongoDB 6.0 repository
              curl -fsSL https://pgp.mongodb.com/server-6.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-6.0.gpg
              echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
              apt-get update -y
              apt-get install -y mongodb-org

              sed -i 's/bindIp: 127.0.0.1/bindIp: 0.0.0.0/' /etc/mongod.conf
              echo -e "\nsecurity:\n  authorization: disabled" >> /etc/mongod.conf
              systemctl start mongod
              systemctl enable mongod

              # Backup script
              cat <<'SCRIPT' > /usr/local/bin/backup_mongo.sh
              #!/bin/bash
              timestamp=$(date +%F-%H-%M)
              mongodump --out /tmp/mongodump-$timestamp
              aws s3 cp /tmp/mongodump-$timestamp s3://wiz-db-backups-victorg/mongodump-$timestamp --recursive
              rm -rf /tmp/mongodump-$timestamp
              SCRIPT

              chmod +x /usr/local/bin/backup_mongo.sh

              # Cron job
              (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/backup_mongo.sh") | crontab -
              EOF

  tags = {
    Name = "MongoDB-6"
  }
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2_instance_profile"
  role = aws_iam_role.ec2_backup_role.name
}

resource "aws_s3_bucket" "db_backups" {
  bucket         = "wiz-db-backups-victorg"
  force_destroy  = true
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.db_backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "mongodb_instance_public_ip" {
  value = aws_instance.mongo_db.public_ip
}

