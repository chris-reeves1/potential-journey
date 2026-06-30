package main

is_deployment if {
  input.kind == "Deployment"
}

deny contains msg if {
  is_deployment
  input.spec.replicas < 1
  msg := sprintf("Deployment %s must have at least 1 replica", [input.metadata.name])
}

deny contains msg if {
  is_deployment
  input.metadata.namespace == "prod"
  input.spec.replicas < 3
  msg := sprintf("Prod deployment %s must have at least 3 replicas", [input.metadata.name])
}

deny contains msg if {
  is_deployment
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container %s must not use the latest image tag", [container.name])
}

deny contains msg if {
  is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.cpu
  msg := sprintf("Container %s must define CPU requests", [container.name])
}

deny contains msg if {
  is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.memory
  msg := sprintf("Container %s must define memory requests", [container.name])
}

deny contains msg if {
  is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("Container %s must define CPU limits", [container.name])
}

deny contains msg if {
  is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container %s must define memory limits", [container.name])
}
