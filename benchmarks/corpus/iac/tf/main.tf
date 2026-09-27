resource "aws_s3_bucket" "b" { bucket = "data" }
resource "aws_s3_bucket_public_access_block" "b" {
  bucket = aws_s3_bucket.b.id
  block_public_acls = false
  block_public_policy = false
}
resource "aws_security_group" "sg" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  engine = "mysql"
  instance_class = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted = false
}
