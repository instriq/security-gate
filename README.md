<p align="center">
  <p align="center"><b>Security Gate</b></p>
  <p align="center">Simple and pratical security gate for Github Security Alerts</p>
  <p align="center">
    <a href="/LICENSE.md">
      <img src="https://img.shields.io/badge/license-MIT-blue.svg">
    </a>
     <a href="https://github.com/instriq/security-gate/releases">
      <img src="https://img.shields.io/badge/version-0.0.1-blue.svg">
    </a>
  </p>
</p>

---

### Summary

This is a project that allows you to use a Security Gate within Github, using Actions and your project's Security Alerts as an information base. Currently only Dependabot Alerts are supported, soon we will have support for Secrets and Security Advisories Alerts.

You can define a vulnerability policy based on impact i.e. the number of vulnerabilities per threat, and automatically block your CI/CD pipeline if these policies are not met. This ensures that your application has greater protection, preventing codes that contain known threats from being deployed in production.

---

### Download and install

```bash
# Download
$ git clone https://github.com/instriq/security-gate && cd security-gate
    
# Install libs dependencies
$ sudo cpanm --installdeps .

# Basic usage
$ perl security-gate.pl --help
```

---

### Github Actions

```yaml
```

---

### Docker container

```
$ docker build -t security-gate .
$ docker run -ti --rm security-gate -t <GITHUB_TOKEN> -r organization/repository --critical 1 --high 1 --medium 2 --low 4
```

---

### Contribution

Your contributions and suggestions are heartily ♥ welcome. [See here the contribution guidelines.](/.github/CONTRIBUTING.md) Please, report bugs via [issues page](https://github.com/instriq/security-gate/issues) and for security issues, see here the [security policy.](/SECURITY.md) (✿ ◕‿◕)

---

### License

This work is licensed under [MIT License.](/LICENSE.md)