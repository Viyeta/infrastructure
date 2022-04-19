region = "us-east-1"
cidr_block = "10.0.0.0/16"
subnet_cidr_block = "10.0.0.0/24"
vpc_name = "ssw590-vpc"
vpc_tag = "ssw590-vpc-prod"    # Change this according to env
subnet_name = "ssw590-subnet"
zonecount = 3   # On need basis
startindex = 0
gateway_name = "ssw590-gateway"
route_table_name = "ssw590-route-table"
route_table_cidr_block = "0.0.0.0/0"
application_security_group_name = "app_sec_group"
db_host = "cluster0.ksehm.mongodb.net"
db_username = "vkansara"
db_password = "7IJ3CKtqOBMso0Sf"
db_name = "whatscooking"
db_port = "0"
ec2_instance_name = "my-ec2-instance"
ami_id = "ami-0a906a8a4f474558a"    # Modify this
ec2_instance_type = "t2.micro"
pub_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/dhicW4Z3xqDJesjDM8wPoi2R9KX7+DS62C+kTdN6Wg8UbkOhVbz4Q/vTyfHBlxCzUmqlYPFKbtx/Yy5qb4k/R/n1yITf6pgciheT7YM0vw56BFvIS3XNNi/g1Z3wpcEtcQMdZ6JzEg18uKEd4PGamRiBfBgJAaXNS6+A2oLs49RyYQVId9yldnVHWLOwosSMntUvBfAbqWyrFARdwYCub6IR/NT+ikgtz3QU/infIhn+m67COsT1yJNdRLPZSgsE1inBXfIGtVSxgNVZuoKCXN6DntRdFmNJkvBbc/NAlJzCBsQlYqfjkOeUEzXvr1v9OzMGW+nSFo974y5MjMBF viyeta@LAPTOP-80GV89VP"
ec2_instance_tag = "EC2WhatsCooking"
s3_iam_profile_name = "s3-iam"
s3_iam_role_name = "EC2-SSW590"
s3_iam_policy_name = "WebAppS3"
s3_code_deploy_role_name = "CodeDeployEC2ServiceRole"
s3_code_deploy_policy_name = "CodeDeploy-EC2-S3"
s3_code_deploy_bucket_name = "codedeploy.prod.viyetakansara.me"  # Change this according to env
circleci_user_name = "cicd"
circleci_upload_to_s3_policy_name = "CircleCI-Upload-To-S3"
circleci_codedeploy_policy_name = "CircleCI-Code-Deploy"
aws_account_id = "249701936981" # Change this according to env
codedeploy_application_name = "whatscooking"
codedeploy_application_topic = "whatscooking-topic"
codedeploy_application_group = "whatscooking-deploy-group"
circleci_ec2_ami_policy_name = "CircleCI-EC2-Ami"
route53_zone_id = "Z05466232A1G13MN5LZN5"   # Change this according to env
route53_domain_name = "prod.viyetakansara.me"   # Change this according to env
cloudwatch_iam_policy_name = "WebAppCloudwatch"
cloudwatch_log_group_name = "whatscookingssw590"
log_retention_days = 7
route53_root_domain_name = "viyetakansara.me"
route53_root_zone_id = "Z09740701GX19S374MH4W"  # For adding DNS record in root account
alb_ssl_cirtificate_arn = "arn:aws:acm:us-east-1:440205144781:certificate/085aaa76-4928-4e99-b600-c25133a43f10"
