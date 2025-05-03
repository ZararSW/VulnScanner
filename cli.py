#!/usr/bin/env python3
"""
Command-line interface for the vulnerability scanner.
"""

import os
import sys
import time
import logging
import argparse
import textwrap
from datetime import datetime
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from scanner import Scanner
from scanner.utils import normalize_url, is_valid_url

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   filename='scanner.log')

console = Console()

def validate_url(url):
    """Validate that the URL is properly formatted."""
    if not url:
        return False
    
    url = normalize_url(url)
    parsed = urlparse(url)
    
    if not parsed.netloc:
        return False
    
    return True

def get_severity_color(severity):
    """Get the color for a severity level."""
    severity = severity.lower()
    if severity == 'critical':
        return 'bright_red'
    elif severity == 'high':
        return 'red'
    elif severity == 'medium':
        return 'yellow'
    elif severity == 'low':
        return 'green'
    else:
        return 'blue'

def print_banner():
    """Print the scanner banner."""
    banner = """
    ██████╗ ██╗   ██╗ ██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔══██╗██║   ██║██╔════╝       ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██████╔╝██║   ██║██║  ███╗█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══██╗██║   ██║██║   ██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝╚██████╔╝      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═════╝  ╚═════╝  ╚═════╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                        
    Advanced Web Vulnerability Scanner with Bug Bounty Methodology
    Version 0.1.0
    """
    console.print(Panel(banner, border_style="blue"))

def scan_target(url, depth='medium', output_file=None):
    """
    Scan a target URL for vulnerabilities.
    
    Args:
        url (str): Target URL to scan
        depth (str): Scan depth (low, medium, high)
        output_file (str): Optional file to write results to
    """
    print_banner()
    
    # Validate URL
    if not validate_url(url):
        console.print(f"[red]Invalid URL: {url}[/red]")
        console.print("[yellow]URLs should be in the format: https://example.com/[/yellow]")
        return
    
    url = normalize_url(url)
    console.print(f"[blue]Target:[/blue] {url}")
    console.print(f"[blue]Scan Depth:[/blue] {depth}")
    console.print()
    
    # Initialize scanner
    scanner = Scanner(url, depth=depth)
    
    # Progress display
    console.print("[bold]Starting scan...[/bold]")
    
    with Progress(
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
    ) as progress:
        scan_task = progress.add_task("[cyan]Scanning...", total=100)
        
        # Start scanner in separate thread
        scanner.start_scan_async()
        
        # Update progress
        while scanner.status != 'completed' and scanner.status != 'failed':
            progress.update(scan_task, completed=scanner.progress)
            time.sleep(1)
        
        # Complete progress
        progress.update(scan_task, completed=100)
    
    # Show results
    vulnerabilities = scanner.vulnerabilities
    recon_data = scanner.recon_data
    
    console.print()
    console.print("[bold green]Scan Completed![/bold green]")
    console.print()
    
    if recon_data:
        console.print(Panel("[bold]Reconnaissance Results[/bold]", border_style="blue"))
        
        # Display subdomains
        if 'subdomains' in recon_data and recon_data['subdomains']:
            console.print("[bold]Subdomains:[/bold]")
            for subdomain in recon_data['subdomains'][:10]:  # Limit to 10 for display
                console.print(f"  • {subdomain}")
            if len(recon_data['subdomains']) > 10:
                console.print(f"  • ...and {len(recon_data['subdomains']) - 10} more")
            console.print()
        
        # Display technologies
        if 'technologies' in recon_data and recon_data['technologies']:
            console.print("[bold]Detected Technologies:[/bold]")
            for tech in recon_data['technologies']:
                console.print(f"  • {tech}")
            console.print()
        
        # Display open ports
        if 'open_ports' in recon_data and recon_data['open_ports']:
            console.print("[bold]Open Ports:[/bold]")
            for ip, ports in recon_data['open_ports'].items():
                if ports:
                    console.print(f"  • {ip}: {', '.join(map(str, ports))}")
            console.print()
    
    # Display vulnerabilities
    if vulnerabilities:
        console.print(Panel(f"[bold]Found {len(vulnerabilities)} Vulnerabilities[/bold]", border_style="red"))
        
        # Group vulnerabilities by severity
        severity_order = ['critical', 'high', 'medium', 'low']
        vulnerabilities_by_severity = {}
        
        for severity in severity_order:
            vulnerabilities_by_severity[severity] = []
            
        for vuln in vulnerabilities:
            severity = vuln['severity'].lower()
            if severity in vulnerabilities_by_severity:
                vulnerabilities_by_severity[severity].append(vuln)
        
        # Display table of vulnerabilities
        table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
        table.add_column("ID", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=15)
        table.add_column("Title", width=40)
        table.add_column("URL", width=40)
        
        vuln_id = 1
        for severity in severity_order:
            for vuln in vulnerabilities_by_severity[severity]:
                severity_text = Text(vuln['severity'].upper(), style=get_severity_color(vuln['severity']))
                table.add_row(
                    str(vuln_id),
                    severity_text,
                    vuln['vulnerability_type'],
                    textwrap.shorten(vuln['title'], width=40),
                    textwrap.shorten(vuln['affected_url'], width=40)
                )
                vuln_id += 1
        
        console.print(table)
        
        # Detailed vulnerability information
        console.print()
        console.print(Panel("[bold]Vulnerability Details[/bold]", border_style="red"))
        
        vuln_id = 1
        for severity in severity_order:
            for vuln in vulnerabilities_by_severity[severity]:
                severity_text = Text(f"Severity: {vuln['severity'].upper()}", style=get_severity_color(vuln['severity']))
                
                console.print(f"[bold][{vuln_id}] {vuln['title']}[/bold]")
                console.print(severity_text)
                console.print(f"[bold]Type:[/bold] {vuln['vulnerability_type']}")
                console.print(f"[bold]URL:[/bold] {vuln['affected_url']}")
                console.print(f"[bold]Description:[/bold] {vuln['description']}")
                
                if 'validation_steps' in vuln and vuln['validation_steps']:
                    console.print("[bold]Validation Steps:[/bold]")
                    console.print(vuln['validation_steps'])
                
                console.print("[bold]Proof of Concept:[/bold]")
                console.print(vuln['proof_of_concept'])
                
                console.print()
                vuln_id += 1
    else:
        console.print(Panel("[bold green]No vulnerabilities found![/bold green]", border_style="green"))
    
    # Save results to file if requested
    if output_file:
        save_results_to_file(url, vulnerabilities, recon_data, output_file)
        console.print(f"[green]Results saved to {output_file}[/green]")

def save_results_to_file(url, vulnerabilities, recon_data, output_file):
    """Save scan results to a file."""
    try:
        with open(output_file, 'w') as f:
            f.write(f"# Vulnerability Scan Report\n\n")
            f.write(f"Target: {url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Reconnaissance Data\n\n")
            
            if 'subdomains' in recon_data and recon_data['subdomains']:
                f.write("### Subdomains\n\n")
                for subdomain in recon_data['subdomains']:
                    f.write(f"- {subdomain}\n")
                f.write("\n")
            
            if 'technologies' in recon_data and recon_data['technologies']:
                f.write("### Technologies\n\n")
                for tech in recon_data['technologies']:
                    f.write(f"- {tech}\n")
                f.write("\n")
            
            if 'open_ports' in recon_data and recon_data['open_ports']:
                f.write("### Open Ports\n\n")
                for ip, ports in recon_data['open_ports'].items():
                    if ports:
                        f.write(f"- {ip}: {', '.join(map(str, ports))}\n")
                f.write("\n")
            
            f.write("## Vulnerabilities\n\n")
            
            if vulnerabilities:
                # Group vulnerabilities by severity
                severity_order = ['critical', 'high', 'medium', 'low']
                vulnerabilities_by_severity = {}
                
                for severity in severity_order:
                    vulnerabilities_by_severity[severity] = []
                    
                for vuln in vulnerabilities:
                    severity = vuln['severity'].lower()
                    if severity in vulnerabilities_by_severity:
                        vulnerabilities_by_severity[severity].append(vuln)
                
                vuln_id = 1
                for severity in severity_order:
                    for vuln in vulnerabilities_by_severity[severity]:
                        f.write(f"### [{vuln_id}] {vuln['title']}\n\n")
                        f.write(f"- **Severity:** {vuln['severity'].upper()}\n")
                        f.write(f"- **Type:** {vuln['vulnerability_type']}\n")
                        f.write(f"- **URL:** {vuln['affected_url']}\n")
                        f.write(f"- **Description:** {vuln['description']}\n\n")
                        
                        if 'validation_steps' in vuln and vuln['validation_steps']:
                            f.write("#### Validation Steps\n\n")
                            f.write(f"{vuln['validation_steps']}\n\n")
                        
                        f.write("#### Proof of Concept\n\n")
                        f.write(f"{vuln['proof_of_concept']}\n\n")
                        
                        f.write("---\n\n")
                        vuln_id += 1
            else:
                f.write("No vulnerabilities found.\n")
    
    except Exception as e:
        console.print(f"[red]Error saving results to file: {str(e)}[/red]")

def main():
    """Main function for the CLI."""
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner with Bug Bounty Methodology')
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-d', '--depth', choices=['low', 'medium', 'high'], default='medium',
                       help='Scan depth (default: medium)')
    parser.add_argument('-o', '--output', help='Output file for scan results')
    
    args = parser.parse_args()
    
    try:
        scan_target(args.url, args.depth, args.output)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
