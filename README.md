# Security Findings Templates

A collection of security vulnerability templates for pentesters, bug bounty hunters, and security researchers. Following templates can also be used for automation with various tools.

> Note: The following project just started and all the **work is in progress [WIP]**. Breaking changes can be expected.

This repository aims to:

1. **Save time** by providing ready-to-use vulnerability templates
2. **Standardize reporting** across different clients and assessments
3. **Improve quality** of security findings with comprehensive fields
4. **Facilitate customization** by providing a base template that can be extended
5. **Support multiple export formats** for integration with various tools and workflows

- **TOML-based templates**: Human-readable, machine-parsable format
- **Categorized findings**: Web, API, Mobile, Infrastructure, and more
- **Extensible structure**: Fork and customize to your needs

The master template includes these key sections:

> Below information covers a vast amount of which i think might be helpful and overkill. But not mandatory. Having data can help in auto populating. Feel free to propose a better solution.

- **Metadata**: Basic information about the finding
- **Classification**: Severity, CVSS, CWE identifiers
- **Affected Components**: Systems and technologies affected
- **Details**: Description, impact, and root cause
- **Reproduction**: Steps to reproduce the vulnerability
- **Proof of Concept**: Code or commands demonstrating the issue
- **Remediation**: Recommendations and example fixes
- **References**: CVEs and other reference materials
- **Communication**: Tracking disclosure details
- **Tracking**: Issue tracking references
- **Compliance**: Regulatory impacts
- **Additional Info**: Notes and related findings
Easy readable and less error prone. Additionally, it can be easily converted to markdown, PDF etc.

Contributions are welcome! Please feel free to submit a Pull Request.

This project is licensed under the MIT License - see the LICENSE file for details.

- OWASP for their security testing methodologies
- The security research community for sharing knowledge.


## Exporters Tools:

### Convert to Markdown

Convert the toml to markdown

``` bash
pip install --user toml
```

``` bash
python exporters/markdown-exporter.py templates/web/sql-injection.toml > sql-finding.md
```

