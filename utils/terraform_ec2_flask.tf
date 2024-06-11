provider "aws" {
  region = var.region_aws
  access_key = var.accessKeyId
  secret_key = var.secretAccessKey
  token = var.sessionToken
  }

resource "aws_cognito_user_pool" "predictia" {
  name = var.cognito_pool_name
  # Enable admin user password authentication
  
}

resource "aws_cognito_user_pool_client" "predictiacognito_client" {
  name = "predictiaappclient"
  user_pool_id = aws_cognito_user_pool.predictia.id
  # Configure other settings as needed
  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  access_token_validity =  3
}

# Create ZIP archive of Lambda function code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "../lambdas-predictia/"  # Path to the directory containing Lambda function code
  output_path = "${path.module}/lambda_function.zip"
}


# Define Lambda function lambda-ids
resource "aws_lambda_function" "lambdaids" { 
  function_name    = "lambda-ids"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda-ids.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  layers           = [var.lambda_layer_pandas]  # ARN of your Lambda layer

  environment {
    variables = {
      BUCKET_NAME = var.bucket_name
    }
  }
}

# Define Lambda function lambda-forecast
resource "aws_lambda_function" "lambdaforecast" { 
  function_name    = "lambda-forecast"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda-forecast.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path  # Path to the ZIP archive of Lambda function code
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  layers           = [var.lambda_layer_pandas]  # ARN of your Lambda layer

  environment {
    variables = {
      BUCKET_NAME = var.bucket_name
    }
  }
}

# Define Lambda function lambda-insights
resource "aws_lambda_function" "lambdainsights" { 
  function_name    = "lambda-insights"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda-insights.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path  # Path to the ZIP archive of Lambda function code
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  layers           = [var.lambda_layer_pandas]  # ARN of your Lambda layer

  environment {
    variables = {
      BUCKET_NAME = var.bucket_name
    }
  }
}

# Define Lambda function lambda-metrics
resource "aws_lambda_function" "lambdametrics" { 
  function_name    = "lambda-metrics"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda-metrics.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path  # Path to the ZIP archive of Lambda function code
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  layers           = [var.lambda_layer_pandas]  # ARN of your Lambda layer

  environment {
    variables = {
      BUCKET_NAME = var.bucket_name
    }
  }
}

# Define Lambda function lambda-metrics
resource "aws_lambda_function" "lambdasendemail" { 
  function_name    = "lambda-email"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda-sendemail.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path  # Path to the ZIP archive of Lambda function code
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      pool_id = aws_cognito_user_pool.predictia.id
    }
  }
}

# Define IAM role for Lambda function
resource "aws_iam_role" "lambda_role" {
  name = "lambda-role"

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "cognito_list_users_policy" {
  name        = "cognito-list-users-policy"
  description = "Allows Lambda execution role to list users in Cognito User Pool"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "cognito-idp:ListUsers"
        Resource = "arn:aws:cognito-idp:${var.region_aws}:${var.aws_account_number}:userpool/${aws_cognito_user_pool.predictia.id}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cognito_list_users_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.cognito_list_users_policy.arn
}


# Attach IAM policy to Lambda role
resource "aws_iam_role_policy_attachment" "lambda_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"  # Attach a read-only S3 access policy
}


resource "aws_instance" "flask_ec2" {
  ami                    = var.ami  
  instance_type          = var.instance_type            
  key_name               = var.ssh_key_pair_name       
  associate_public_ip_address = true      

  
  provisioner "remote-exec" {
    inline = [
      # Install required packages
      "sudo apt-get update -y",
      "sudo apt-get install -y python3 git",
      "curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py",
      "sudo python3 get-pip.py",
      "sudo apt-get install -y python3-venv",  # Install python3-venv package for virtual environments

      "echo \"export AWS_ACCESS_KEY_ID=${var.accessKeyId}\" >> ~/.bashrc",
      "echo \"export AWS_SECRET_ACCESS_KEY=${var.secretAccessKey}\" >> ~/.bashrc",
      "echo \"export AWS_SESSION_TOKEN=${var.sessionToken}\" >> ~/.bashrc",
      "echo \"export AWS_REGION=${var.region_aws}\" >> ~/.bashrc",
      "echo \"export client_id=${aws_cognito_user_pool_client.predictiacognito_client.id}\" >> ~/.bashrc",
      "echo \"export user_pool=${aws_cognito_user_pool.predictia.id}\" >> ~/.bashrc",

      # Clone Flask application from GitHub
      "git clone ${var.github_repo} /home/ubuntu/flask_app",
      
      # Create and activate virtual environment
      "cd /home/ubuntu/flask_app",
      "python3 -m venv venv",
      "source venv/bin/activate",
      
      # Install dependencies
      "pip install -r requirements.txt",

      "sudo ufw allow 5000",

      # Create a systemd service for Gunicorn
      "cat <<EOF | sudo tee /etc/systemd/system/flask_app.service",
      "[Unit]",
      "Description=Gunicorn instance to serve Flask application",
      "After=network.target",

      "[Service]",
      "User=ubuntu",
      "Group=ubuntu",
      "WorkingDirectory=/home/ubuntu/flask_app",
      "Environment=\"PATH=/home/ubuntu/flask_app/venv/bin\"",
      "ExecStart=/home/ubuntu/.local/bin/gunicorn -w 1 -b 0.0.0.0:5000 -e bucket_name=${var.bucket_name} -e region_aws=${var.region_aws} -e accessKeyId=${var.accessKeyId} -e secretAccessKey=${var.secretAccessKey} -e sessionToken=${var.sessionToken} -e client_id=${aws_cognito_user_pool_client.predictiacognito_client.id} -e user_pool=${aws_cognito_user_pool.predictia.id} -e lambda_forecast_arn=${aws_lambda_function.lambdaforecast.arn} -e lambda_get_ids_arn=${aws_lambda_function.lambdaids.arn} -e lambda_get_insights=${aws_lambda_function.lambdainsights.arn} -e lambda_get_metrics=${aws_lambda_function.lambdametrics.arn} app:app",
      "Restart=always",

      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",

      # Start and enable the Gunicorn service
      "sudo systemctl daemon-reload",
      "sudo systemctl start flask_app",
      "sudo systemctl enable flask_app",
    ]
    
    connection {
      type        = "ssh"
      user        = "ubuntu"  # SSH username for Amazon Linux, CentOS, or Red Hat AMIs
      private_key = file(var.private_key_ec2_path)  # Replace with the path to your SSH private key file
      host        = self.public_ip
    }
  }

  tags = {
    Name = "PredictIA-Flask-Ubuntu"
  }

  vpc_security_group_ids = [aws_security_group.flask_sg_predictia.id]
              
}

resource "aws_security_group" "flask_sg_predictia" {
  name        = "flask_sg_predictia"
  description = "Security group for Flask EC2 instance"

  // Ingress rule to allow HTTP traffic from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  // Allow traffic from any IPv4 address
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"   // Allow all protocols
    cidr_blocks     = ["0.0.0.0/0"]  // Allow traffic to any IPv4 address
  }
}

output "public_ip" {
  value = aws_instance.flask_ec2.public_ip
}

output "lambda_get_ids_arn" {
  value = aws_lambda_function.lambdaids.arn
}

output "lambda_forecast_arn" {
  value = aws_lambda_function.lambdaforecast.arn
}

output "lambda_insights_arn" {
  value = aws_lambda_function.lambdainsights.arn
}

output "lambda_emails_arn" {
  value = aws_lambda_function.lambdasendemail.arn
}

output "lambda_metrics_arn" {
  value = aws_lambda_function.lambdametrics.arn
}