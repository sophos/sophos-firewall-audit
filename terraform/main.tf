resource "null_resource" "run_python_script" {
  provisioner "local-exec" {
    command = "./run_pipeline.sh"
    interpreter = ["/bin/bash", "-c"]
  }
    triggers = {
    always_run = timestamp()
  }
}