output "service_public_ip" {
  description = "DNS A 레코드에 연결할 서비스 IP"
  value       = aws_eip.service.public_ip
}

output "service_instance_id" {
  value = aws_instance.service.id
}

output "target_private_ips" {
  value = aws_instance.target[*].private_ip
}

output "target_instance_ids" {
  value = aws_instance.target[*].id
}

output "backup_bucket" {
  value = aws_s3_bucket.backup.id
}
