<p align="center">
  <p align="center"><b>Security Gate</b></p>
  <p align="center">Simple and pratical security gate for Github Security Alerts</p>
  <p align="center">
    <a href="/LICENSE.md">
      <img src="https://img.shields.io/badge/license-MIT-blue.svg">
    </a>
     <a href="https://github.com/instriq/security-gate/releases">
      <img src="https://img.shields.io/badge/version-0.0.3-blue.svg">
    </a>
  </p>
</p>

---

### Summary

This is a project that allows you to use a Security Gate within Github, using Actions and your project's Security Alerts as an information base. Currently only Dependabot Alerts are supported, soon we will have support for Secrets and Security Advisories Alerts.

You can define a vulnerability policy based on impact i.e. the number of vulnerabilities per threat, and automatically block your CI/CD pipeline if these policies are not met. This ensures that your application has greater protection, preventing codes that contain known threats from being deployed in production.

---

### Github Actions

You need to create a token with read access to Security Alerts and configure it within the Secrets resource of your repository, then:
In your repository, create a YAML file at: ```.github/workflows/security-gate.yml``` with this content:

```yaml
name: Security Gate - Instriq

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      MAX_CRITICAL: 1
      MAX_HIGH: 2
      MAX_MEDIUM: 3
      MAX_LOW: 4
      GITHUB_TOKEN: ${{ secrets.TOKEN }}
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Pull Docker image from GitHub Container Registry
      run: docker pull ghcr.io/instriq/security-gate/security-gate:latest

    - name: Verify security alerts from dependabot
      run: |
        docker run ghcr.io/instriq/security-gate/security-gate:latest \
        -t $GITHUB_TOKEN \
        -r ${{ github.repository }} \
        --critical $MAX_CRITICAL \
        --high $MAX_HIGH \
        --medium $MAX_MEDIUM \
        --low $MAX_LOW
```

---

### If you want to use local

```bash
# Download
$ git clone https://github.com/instriq/security-gate && cd security-gate
    
# Install libs dependencies
$ sudo cpanm --installdeps .

# Basic usage
$ perl security-gate.pl --help

Security Gate v0.0.3
Core Commands
==============
	Command          Description
	-------          -----------
        -t, --token      GitHub token
        -r, --repo       GitHub repository
        -c, --critical   Critical severity limit
        -h, --high       High severity limit
        -m, --medium     Medium severity limit
        -l, --low        Low severity limit 
```

---

### Docker container

```
$ docker build -t security-gate .
$ docker run -ti --rm security-gate -t <GITHUB_TOKEN> -r <organization/repository> --critical 1 --high 2 --medium 3 --low 5
```

---

### Contribution

Your contributions and suggestions are heartily ♥ welcome. [See here the contribution guidelines.](/.github/CONTRIBUTING.md) Please, report bugs via [issues page](https://github.com/instriq/security-gate/issues) and for security issues, see here the [security policy.](/SECURITY.md) (✿ ◕‿◕)

---

### License

This work is licensed under [MIT License.](/LICENSE.md)