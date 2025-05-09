#!/usr/bin/env python3
"""
TOML to Markdown Vulnerability Report Exporter

This script converts TOML-formatted vulnerability templates into
professional Markdown reports suitable for delivery to clients.

Usage:
    python markdown-exporter.py input.toml > output.md
"""

import sys
import os
import argparse
import toml
import datetime
from typing import Dict, Any, List


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Convert TOML vulnerability templates to Markdown reports"
    )
    parser.add_argument(
        "input_file", help="Input TOML vulnerability template file"
    )
    parser.add_argument(
        "-o", "--output", help="Output Markdown file (default: stdout)"
    )
    parser.add_argument(
        "--company-name", help="Your company name for the report header"
    )
    parser.add_argument(
        "--logo", help="Path to company logo for inclusion in the report"
    )
    return parser.parse_args()


def read_template(file_path: str) -> Dict[str, Any]:
    """Read and parse the TOML template file."""
    try:
        with open(file_path, "r") as f:
            return toml.load(f)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found", file=sys.stderr)
        sys.exit(1)
    except toml.TomlDecodeError as e:
        print(f"Error parsing TOML file: {e}", file=sys.stderr)
        sys.exit(1)


def generate_cvss_color(score: float) -> str:
    """Generate a color based on CVSS score."""
    if score >= 9.0:
        return "🔴 Critical"
    elif score >= 7.0:
        return "🟠 High"
    elif score >= 4.0:
        return "🟡 Medium"
    elif score > 0.0:
        return "🟢 Low"
    else:
        return "⚪ None"


def format_list(items: List[str]) -> str:
    """Format a list of items into a Markdown list."""
    if not items:
        return "_None_"
    return "\n".join(f"- {item}" for item in items)


def generate_markdown(data: Dict[str, Any], company_name: str = None, logo_path: str = None) -> str:
    """
    Generate Markdown output from the TOML data.
    """
    # Start with the report header
    now = datetime.datetime.now().strftime("%Y-%m-%d")
    
    md = []
    
    # Add logo if provided
    if logo_path and os.path.exists(logo_path):
        md.append(f"![{company_name or 'Security'} Logo]({logo_path})\n")
    
    # Report header
    md.append(f"# Security Vulnerability Report: {data['metadata']['title']}")
    md.append(f"**Report Date:** {now}")
    if company_name:
        md.append(f"**Prepared by:** {company_name}")
    md.append(f"**Finding ID:** {data['metadata']['finding_id']}")
    md.append("")
    
    # Executive Summary section
    md.append("## Executive Summary")
    md.append("")
    md.append(f"**Severity:** {data['classification']['severity'].capitalize()}")
    
    if 'cvss_score' in data['classification']:
        cvss = data['classification']['cvss_score']
        md.append(f"**CVSS Score:** {cvss} ({generate_cvss_color(cvss)})")
    
    if 'cvss_vector' in data['classification']:
        md.append(f"**CVSS Vector:** `{data['classification']['cvss_vector']}`")
    
    md.append("")
    md.append(data['details']['description'])
    md.append("")
    
    # Affected Components
    md.append("## Affected Components")
    md.append("")
    md.append(f"**System:** {data['affected_components']['system'] or 'Not specified'}")
    md.append(f"**Component:** {data['affected_components']['component'] or 'Not specified'}")
    md.append(f"**Version:** {data['affected_components']['version'] or 'Not specified'}")
    md.append(f"**Location:** {data['affected_components']['location'] or 'Not specified'}")
    
    if data['affected_components']['endpoints']:
        md.append("\n**Affected Endpoints:**")
        md.append(format_list(data['affected_components']['endpoints']))
    
    if data['affected_components']['technologies']:
        md.append("\n**Technologies:**")
        md.append(format_list(data['affected_components']['technologies']))
    
    md.append("")
    
    # Vulnerability Details
    md.append("## Vulnerability Details")
    md.append("")
    md.append("### Impact")
    md.append(data['details']['impact'])
    md.append("")
    md.append("### Root Cause")
    md.append(data['details']['root_cause'])
    md.append("")
    
    # Classification Details
    md.append("### Classification")
    md.append(f"- **CWE ID:** [CWE-{data['classification']['cwe_id']}](https://cwe.mitre.org/data/definitions/{data['classification']['cwe_id']}.html): {data['classification']['cwe_name']}")
    md.append(f"- **OWASP Category:** {data['classification']['owasp_category']}")
    md.append("")
    
    # Reproduction
    md.append("## Reproduction")
    md.append("")
    md.append("### Prerequisites")
    md.append(data['reproduction']['preconditions'])
    md.append("")
    md.append("### Steps to Reproduce")
    for i, step in enumerate(data['reproduction']['steps'], 1):
        md.append(f"{i}. {step}")
    md.append("")
    
    if data['reproduction']['payload']:
        md.append("### Payload")
        md.append("```")
        md.append(data['reproduction']['payload'])
        md.append("```")
        md.append("")
    
    # Proof of Concept
    md.append("## Proof of Concept")
    md.append("")
    
    if data['proof_of_concept']['code']:
        md.append("### Code")
        md.append("```")
        md.append(data['proof_of_concept']['code'])
        md.append("```")
        md.append("")
    
    if data['proof_of_concept']['curl_command']:
        md.append("### HTTP Request")
        md.append("```bash")
        md.append(data['proof_of_concept']['curl_command'])
        md.append("```")
        md.append("")
    
    # Remediation
    md.append("## Remediation")
    md.append("")
    md.append("### Recommendation")
    md.append(data['remediation']['recommendation'])
    md.append("")
    
    if data['remediation']['code_fix']:
        md.append("### Example Fix")
        md.append("```")
        md.append(data['remediation']['code_fix'])
        md.append("```")
        md.append("")
    
    md.append(f"**Estimated Effort:** {data['remediation']['estimated_effort'].capitalize()}")
    md.append(f"**Timeline:** {data['remediation']['timeline']}")
    md.append("")
    
    # References
    md.append("## References")
    md.append("")
    
    if data['references']['cve_ids']:
        md.append("### CVE IDs")
        md.append(format_list(data['references']['cve_ids']))
        md.append("")
    
    if data['references']['external_references']:
        md.append("### External References")
        md.append(format_list(data['references']['external_references']))
        md.append("")
    
    # Additional sections for specialized template fields
    for section_name, section_data in data.items():
        if section_name not in [
            "metadata", "classification", "affected_components", "details", 
            "reproduction", "proof_of_concept", "remediation", "references", 
            "communication", "tracking", "compliance", "additional_info"
        ]:
            md.append(f"## {section_name.replace('_', ' ').title()}")
            md.append("")
            for field_name, field_value in section_data.items():
                field_title = field_name.replace('_', ' ').title()
                if isinstance(field_value, list):
                    md.append(f"### {field_title}")
                    md.append(format_list(field_value))
                elif isinstance(field_value, str) and field_value.strip():
                    md.append(f"### {field_title}")
                    md.append(field_value)
                elif isinstance(field_value, (int, float, bool)):
                    md.append(f"**{field_title}:** {field_value}")
                md.append("")
    
    # Compliance Information
    if 'compliance' in data:
        md.append("## Compliance Impact")
        md.append("")
        
        if data['compliance']['regulatory_impact']:
            md.append("### Regulatory Impact")
            md.append(format_list(data['compliance']['regulatory_impact']))
            md.append("")
        
        md.append(f"**Business Impact:** {data['compliance']['business_impact'].capitalize()}")
        md.append(f"**Data Breach Risk:** {'Yes' if data['compliance']['data_breach_risk'] else 'No'}")
        md.append("")
    
    # Additional Information
    if data['additional_info']['notes']:
        md.append("## Additional Notes")
        md.append("")
        md.append(data['additional_info']['notes'])
        md.append("")
    
    if data['additional_info']['tags']:
        md.append("**Tags:** " + ", ".join(f"`{tag}`" for tag in data['additional_info']['tags']))
        md.append("")
    
    # Footer
    md.append("---")
    md.append(f"Report generated on {now}" + (f" by {company_name}" if company_name else ""))
    
    return "\n".join(md)


def main() -> None:
    """Main entry point."""
    args = parse_args()
    data = read_template(args.input_file)
    
    markdown_output = generate_markdown(data, args.company_name, args.logo)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(markdown_output)
        print(f"Report saved to {args.output}")
    else:
        print(markdown_output)


if __name__ == "__main__":
    main()