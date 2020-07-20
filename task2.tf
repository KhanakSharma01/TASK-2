provider "aws" {
region = "ap-south-1"
profile = "KS"
}

resource "aws_vpc" "my_vpc" {
  cidr_block       = "192.168.0.0/16"
  instance_tenancy = "default"
  enable_dns_hostnames = "true"
  tags = {
    Name = "myvpc2"
  }
}

resource "aws_subnet" "vpc_subnet" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = "192.168.0.0/24"
  availability_zone = "ap-south-1a"
  map_public_ip_on_launch = "true"

  tags = {
    Name = "subnet_1"
  }
}


//Creation of Security-Groups

resource "aws_security_group" "security" {
name = "firewall-NFS"
vpc_id = aws_vpc.my_vpc.id
description = "allow NFS"

ingress {
description = "NFS"
from_port = 2049
to_port = 2049
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

ingress {
description = "HTTP"
from_port = 80
to_port = 80
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

ingress {
description = "SSH"
from_port = 22
to_port = 22
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

egress {
from_port= 0
to_port = 0
protocol = "-1"
cidr_blocks = [ "0.0.0.0/0" ]
}

tags = {
Name = "firewall_nfs"
}
}

resource "aws_efs_file_system" "new_efs" {
creation_token = "efs"

tags = {
Name = "new_efs"
}
}


resource "aws_efs_mount_target" "mount_EFS" {
file_system_id = aws_efs_file_system.new_efs.id
subnet_id = aws_subnet.vpc_subnet.id
security_groups = [ aws_security_group.security.id ]
}

resource "aws_internet_gateway" "inter_gateway" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "my_ig"
  }
}

resource "aws_route_table" "rt_tb" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    
gateway_id = aws_internet_gateway.inter_gateway.id
    cidr_block = "0.0.0.0/0"
  }

    tags = {
    Name = "myroute-table"
  }
}

resource "aws_route_table_association" "rt_associate" {
  subnet_id      = aws_subnet.vpc_subnet.id
  route_table_id = aws_route_table.rt_tb.id
}


resource "aws_instance" "ks_task2_instance" {
depends_on = [ aws_efs_mount_target.mount_EFS ]
ami = "ami-0447a12f28fddb066"
instance_type = "t2.micro"
key_name = "key1"
subnet_id = aws_subnet.vpc_subnet.id
vpc_security_group_ids = [ aws_security_group.security.id ]

user_data = <<-EOF
      #! /bin/bash
	sudo su - root
	sudo yum install httpd -y
        sudo service httpd start
	sudo service httpd enable
 	sudo yum install git -y
        sudo yum install -y amazon-efs-utils 
        sudo mount -t efs "${aws_efs_file_system.new_efs.id}":/ /var/www/html
	mkfs.ext4 /dev/sdf	
	mount /dev/sdf /var/www/html
	cd /var/www/html
	git clone https://github.com/KhanakSharma01/TASK-2.git
	  
EOF
}

resource "aws_s3_bucket" "tbks" {
  bucket = "tbks"
  acl    = "public-read"

  tags = {
    Name = "My bucket"
  }
}

 
//Block Public Access


resource "aws_s3_bucket_public_access_block" "tbks" {

bucket = aws_s3_bucket.tbks.id
block_public_policy = true
}

locals {
s3_origin_id = "S3-${aws_s3_bucket.tbks.bucket}"
}


//Creation Of CloudFront


resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
comment = "bucket_ks"
}

resource "aws_cloudfront_distribution" "cloudfront" {
    origin {
        domain_name = aws_s3_bucket.tbks.bucket_regional_domain_name
        origin_id = local.s3_origin_id
 
        s3_origin_config {

origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
}
}
 enabled = true
is_ipv6_enabled = true
comment = "access"


    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = local.s3_origin_id

        # Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
        
        cookies {
	forward = "none"
            }
        }

        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
         max_ttl = 86400
    }
# Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }
    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }

    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
retain_on_delete = true

}


resource "aws_codepipeline" "codepipeline" {
  name     = "ks"
  role_arn = "arn:aws:iam::947849437392:role/service-role/AWSCodePipelineServiceRole-ap-south-1-kspipe"
   artifact_store {
    location = "${aws_s3_bucket.tbks.bucket}"
    type     = "S3"
	}
	 
	 stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["SourceArtifacts"]
configuration = {
        Owner  = "KhanakSharma01"
        Repo   = "TASK-2"
        Branch = "master"
	OAuthToken = "d361b3570f842027691cbd9aabdc8f91a23aa318"        
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "S3"
      version         = "1"
      input_artifacts = ["SourceArtifacts"]	
		configuration = {
        BucketName = "${aws_s3_bucket.tbks.bucket}"
        Extract = "true"
      }
      
    }
  }
}
