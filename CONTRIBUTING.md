# Contributing to PayloadZer0 KEV Threat Scanner

Thank you for your interest in contributing! This document provides guidelines for contributions.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - OS and Python version
   - Nuclei version
   - Steps to reproduce
   - Expected vs actual behavior
   - Logs (sanitize sensitive data)

### Suggesting Features

1. Check existing feature requests
2. Describe the use case clearly
3. Explain why it benefits the community
4. Consider implementation complexity

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Update documentation
6. Commit with clear messages
7. Push to your fork
8. Open a Pull Request

### Code Style

- Follow PEP 8 for Python code
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and modular
- Comment complex logic

### Testing

Before submitting:
```bash
# Test basic functionality
python3 payloadZer0.py -t test_hosts.txt --force-scan

# Test utilities
python3 kev_utils.py report
python3 kev_utils.py export

# Test dashboard
python3 monitor_dashboard.py
```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/PayloadZer0.git
cd PayloadZer0

# Install dependencies
pip install -r requirements.txt

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Run tests
python3 payloadZer0.py --help
```

## Areas Needing Contribution

### High Priority
- [ ] Docker support and Dockerfile
- [ ] Configuration file support (YAML/JSON)
- [ ] Proxy support for corporate environments
- [ ] Multiple notification channels (Slack, Discord, Email)
- [ ] Better error recovery and retry logic

### Medium Priority
- [ ] Web UI for results visualization
- [ ] Database backend (SQLite/PostgreSQL)
- [ ] API endpoint for integration
- [ ] Scheduled scanning with cron-like syntax
- [ ] Custom template support

### Nice to Have
- [ ] Ansible playbook for deployment
- [ ] Kubernetes deployment manifests
- [ ] Grafana dashboard templates
- [ ] Integration with vulnerability management platforms
- [ ] Machine learning for false positive reduction

## Feature Ideas

We welcome ideas in these areas:
- Additional notification channels
- Integration with other security tools
- Performance optimizations
- Better reporting formats
- Enhanced filtering and search
- Multi-tenancy support
- RBAC for team environments

## Documentation

When adding features:
- Update README.md with new usage examples
- Add to DEPLOYMENT.md if deployment changes
- Update QUICKSTART.md for new quick wins
- Add inline code comments
- Include docstrings

## Code of Conduct

### Our Standards

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy toward other contributors

### Unacceptable Behavior

- Trolling, insulting, or derogatory comments
- Personal or political attacks
- Public or private harassment
- Publishing others' private information
- Unethical use suggestions

## Questions?

- Open a discussion on GitHub
- Check existing documentation
- Review closed issues for similar questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be:
- Added to CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation (if significant contribution)

Thank you for making this tool better! 🚀
