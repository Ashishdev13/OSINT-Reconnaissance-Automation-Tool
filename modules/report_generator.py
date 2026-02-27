"""
HTML Report Generator
Renders a clean HTML report from all recon findings using Jinja2.
"""

import os
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from .models import ReconResult
import config


class ReportGenerator:
    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(config.TEMPLATES_DIR),
            autoescape=True,
        )

    def generate(self, recon: ReconResult) -> str:
        """Render and save HTML report. Returns the output file path."""
        os.makedirs(config.REPORTS_DIR, exist_ok=True)
        template = self.env.get_template("report.html")

        context = {
            "domain": recon.domain,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "whois": recon.whois,
            "dns": recon.dns,
            "subdomains": recon.subdomains,
            "emails": recon.emails,
            "tech": recon.tech,
            "port_scan": recon.port_scan,
            "shodan": recon.shodan,
        }

        html = template.render(**context)
        filename = f"{recon.domain.replace('.', '_')}_osint_report.html"
        output_path = os.path.join(config.REPORTS_DIR, filename)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path
