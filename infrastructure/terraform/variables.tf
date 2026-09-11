variable "aws_region" {
  description = "배포할 AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "project_name" {
  description = "리소스 이름 접두사"
  type        = string
  default     = "eolwatch"
}

variable "service_instance_type" {
  description = "웹/API/DB 서비스 인스턴스 유형"
  type        = string
  default     = "t4g.micro"
}

variable "target_instance_type" {
  description = "시연용 점검 대상 인스턴스 유형"
  type        = string
  default     = "t4g.micro"
}

variable "target_instance_count" {
  description = "시연용 점검 대상 EC2 수"
  type        = number
  default     = 3
  validation {
    condition     = var.target_instance_count >= 0 && var.target_instance_count <= 3
    error_message = "점검 대상은 0~3대로 제한합니다."
  }
}

variable "root_volume_gb" {
  description = "EC2 루트 볼륨 크기"
  type        = number
  default     = 16
}
