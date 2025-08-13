#!/usr/bin/env python3
"""
Simple Root Certificate Extractor
Usage: python extract_cert.py hostname:port
Example: python extract_cert.py abc.estsecurity.com:1234

Note: Certificate chain extraction using built-in SSL requires Python 3.13+
For older versions, uses OpenSSL command (likely more reliable)

=== LIBRARY USAGE ===
This script can also be used as a library in your own Python projects:

1. Basic usage:
   from extract_cert import extract_root_certificate
   success = extract_root_certificate("example.com:443")

2. Get certificate as string instead of saving to file:
   from extract_cert import extract_root_cert_openssl, extract_root_cert_builtin
   cert_pem = extract_root_cert_openssl("example.com", 443)
   if cert_pem:
       print("Got certificate:", cert_pem)

3. Parse multiple targets:
   from extract_cert import parse_target, extract_root_cert_openssl
   
   targets = ["site1.com", "site2.com:8443", "site3.com:9000"]
   for target in targets:
       hostname, port = parse_target(target)
       cert = extract_root_cert_openssl(hostname, port)
       if cert:
           # Do something with cert
           pass

4. Integration example for certificate validation:
   import extract_cert
   
   def validate_site_certificate(url):
       # Extract root cert from problematic site
       cert_pem = extract_cert.extract_root_cert_openssl("internal.company.com", 443)
       
       if cert_pem:
           # Save to temp file for system installation
           import tempfile
           with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
               f.write(cert_pem)
               return f.name  # Return path for manual installation
       return None

5. Batch processing:
   from extract_cert import extract_root_cert_openssl, save_certificate
   
   sites = ["internal1.company.com", "internal2.company.com", "test.company.com"]
   
   for site in sites:
       cert = extract_root_cert_openssl(site, 443)
       if cert:
           filename = f"{site}_root.crt"
           save_certificate(cert, filename)
           print(f"Saved {filename}")

6. Error handling:
   from extract_cert import extract_root_cert_openssl
   
   try:
       cert = extract_root_cert_openssl("problematic-site.com", 443)
       if cert:
           print("Success!")
       else:
           print("Failed to extract certificate")
   except Exception as e:
       print(f"Error: {e}")

7. Custom certificate analysis:
   from extract_cert import extract_root_cert_openssl, parse_certificate_info
   
   cert_pem = extract_root_cert_openssl("example.com", 443)
   if cert_pem:
       subject, issuer = parse_certificate_info(cert_pem)
       print(f"Certificate issued by: {issuer}")
       print(f"Certificate for: {subject}")

=== API REFERENCE ===
Main functions you can import:

- extract_root_certificate(target) -> bool
  Complete workflow: extract and save root cert from "hostname:port" string
  
- extract_root_cert_openssl(hostname, port) -> str or None
  Extract root certificate PEM using OpenSSL command
  
- extract_root_cert_builtin(hostname, port) -> str or None  
  Extract root certificate using Python 3.13+ built-in SSL (if available)
  
- parse_target(target) -> tuple(hostname, port)
  Parse "hostname:port" string, defaults port to 443
  
- save_certificate(cert_pem, filename) -> bool
  Save PEM certificate string to file
  
- parse_certificate_info(cert_pem) -> tuple(subject, issuer)
  Extract subject and issuer from PEM certificate

Author: jjw(@thejjw)
Last Edit: 2025-08
SPDX-License-Identifier: zlib-acknowledgement
"""

import ssl
import socket
import sys
import subprocess
import re

def extract_root_cert_builtin(hostname, port=443):
    """
    Extract root certificate using Python 3.13+ built-in SSL methods
    
    Args:
        hostname (str): Target hostname
        port (int): Target port (default 443)
        
    Returns:
        str: Root certificate in PEM format, or None if failed
        
    Note:
        Only works with Python 3.13+. Returns None for older versions.
    """
    try:
        print(f"🔍 Using Python 3.13+ SSL methods for {hostname}:{port}...")
        
        # Create context that ignores certificate errors
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate chain
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Use Python 3.13+ method
                cert_chain = ssock.get_unverified_chain()
                
                if not cert_chain:
                    return None
                
                print(f"✅ Found {len(cert_chain)} certificates in chain")
                
                # Convert DER bytes to PEM and find root
                pem_certs = []
                for i, cert_der in enumerate(cert_chain):
                    # Convert DER to PEM
                    pem_data = ssl.DER_cert_to_PEM_cert(cert_der)
                    pem_certs.append(pem_data)
                    print(f"📜 Certificate {i+1}: Converted to PEM")
                
                # Root certificate is typically the last one
                root_cert_pem = pem_certs[-1]
                return root_cert_pem
                
    except AttributeError:
        # get_unverified_chain() not available (Python < 3.13)
        return None
    except Exception as e:
        print(f"❌ Python built-in method failed: {e}")
        return None

def extract_root_cert_openssl(hostname, port=443):
    """
    Extract root certificate using OpenSSL command
    
    Args:
        hostname (str): Target hostname
        port (int): Target port (default 443)
        
    Returns:
        str: Root certificate in PEM format, or None if failed
        
    Note:
        Requires OpenSSL to be installed and available in PATH.
        This is the most reliable method across all Python versions.
    """
    try:
        print(f"🔧 Using OpenSSL for {hostname}:{port}...")
        
        # Run the OpenSSL command
        cmd = [
            'openssl', 's_client', '-showcerts',
            '-servername', hostname,
            '-connect', f'{hostname}:{port}'
        ]
        
        result = subprocess.run(cmd, input='', text=True, capture_output=True, timeout=30)
        
        if result.returncode != 0:
            print(f"❌ OpenSSL failed: {result.stderr}")
            return None
        
        # Extract all certificates from output
        cert_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
        certificates = re.findall(cert_pattern, result.stdout, re.DOTALL)
        
        if not certificates:
            print("❌ No certificates found in OpenSSL output")
            return None
        
        print(f"✅ Found {len(certificates)} certificates")
        
        # Analyze certificates to identify root
        for i, cert_pem in enumerate(certificates):
            subject, issuer = parse_certificate_info(cert_pem)
            print(f"📜 Certificate {i+1}:")
            print(f"   Subject: {subject}")
            print(f"   Issuer:  {issuer}")
            
            if subject == issuer:
                print(f"   🏛️  ROOT Certificate (Self-signed)")
            elif i == len(certificates) - 1:
                print(f"   🏛️  ROOT Certificate (Chain end)")
            elif i == 0:
                print(f"   🍃 LEAF Certificate")
            else:
                print(f"   🔗 INTERMEDIATE Certificate")
        
        # Find root certificate (self-signed first, then last in chain)
        root_cert = None
        for cert_pem in reversed(certificates):
            subject, issuer = parse_certificate_info(cert_pem)
            if subject == issuer:  # Self-signed = root
                root_cert = cert_pem
                break
        
        if not root_cert:
            root_cert = certificates[-1]  # Last in chain
        
        # Clean up the certificate formatting
        lines = [line.strip() for line in root_cert.split('\n') if line.strip()]
        return '\n'.join(lines)
        
    except subprocess.TimeoutExpired:
        print("❌ OpenSSL command timed out")
        return None
    except FileNotFoundError:
        print("❌ OpenSSL not found in PATH")
        print("   Please install OpenSSL or use manual method:")
        print(f"   openssl s_client -showcerts -servername {hostname} -connect {hostname}:{port}")
        return None
    except Exception as e:
        print(f"❌ OpenSSL method failed: {e}")
        return None

def parse_certificate_info(cert_pem):
    """
    Extract subject and issuer from PEM certificate using OpenSSL
    
    Args:
        cert_pem (str): Certificate in PEM format
        
    Returns:
        tuple: (subject, issuer) strings, or ("Unknown", "Unknown") if failed
    """
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject', '-issuer'],
            input=cert_pem,
            text=True,
            capture_output=True,
            timeout=10
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            subject = "Unknown"
            issuer = "Unknown"
            
            for line in lines:
                if line.startswith('subject='):
                    subject = line.replace('subject=', '').strip()
                elif line.startswith('issuer='):
                    issuer = line.replace('issuer=', '').strip()
            
            return subject, issuer
        
    except Exception:
        pass
    
    return "Unknown", "Unknown"

def save_certificate(cert_pem, filename):
    """
    Save certificate to file
    
    Args:
        cert_pem (str): Certificate in PEM format
        filename (str): Output filename
        
    Returns:
        bool: True if successful, False if failed
    """
    try:
        with open(filename, 'w') as f:
            f.write(cert_pem)
            if not cert_pem.endswith('\n'):
                f.write('\n')
        return True
    except Exception as e:
        print(f"❌ Failed to save: {e}")
        return False

def parse_target(target):
    """
    Parse hostname:port from various formats
    
    Args:
        target (str): Target in format "hostname" or "hostname:port"
        
    Returns:
        tuple: (hostname, port) where port defaults to 443
        
    Examples:
        parse_target("example.com") -> ("example.com", 443)
        parse_target("test.com:8443") -> ("test.com", 8443)
    """
    if ':' in target:
        parts = target.split(':')
        if len(parts) == 2:
            try:
                return parts[0], int(parts[1])
            except ValueError:
                pass
    
    # Default to port 443
    return target, 443

def extract_root_certificate(target):
    """
    Main function to extract root certificate (complete workflow)
    
    Args:
        target (str): Target in format "hostname" or "hostname:port"
        
    Returns:
        bool: True if certificate was successfully extracted and saved, False otherwise
        
    Note:
        This function handles the complete workflow:
        1. Parse target hostname:port
        2. Try Python 3.13+ method (if available)
        3. Fall back to OpenSSL method
        4. Save certificate to {hostname}_root.crt file
        5. Display results
    """
    hostname, port = parse_target(target)
    
    print(f"🎯 Target: {hostname}:{port}")
    print(f"🐍 Python version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    cert_pem = None
    
    # Try Python 3.13+ built-in method first
    if sys.version_info >= (3, 13):
        print("\n✅ Trying Python 3.13+ built-in SSL methods...")
        cert_pem = extract_root_cert_builtin(hostname, port)
    else:
        print(f"\n📝 Python {sys.version_info.major}.{sys.version_info.minor} detected - skipping built-in SSL (need 3.13+)")
    
    # Fall back to OpenSSL (works for all Python versions)
    if not cert_pem:
        print("\n🔧 Using OpenSSL command...")
        cert_pem = extract_root_cert_openssl(hostname, port)
    
    if not cert_pem:
        print("❌ Failed to extract root certificate")
        return False
    
    # Save certificate
    output_file = f"{hostname}_root.crt"
    if save_certificate(cert_pem, output_file):
        print(f"\n🎉 SUCCESS!")
        print(f"📁 Root certificate saved: {output_file}")
        print(f"🔧 Install: certlm.msc → Trusted Root CA → Import")
        
        # Show certificate preview
        print(f"\n📋 Certificate preview:")
        lines = cert_pem.split('\n')
        for i, line in enumerate(lines[:3]):  # Show first 3 lines
            print(f"   {line}")
        if len(lines) > 6:
            print("   ...")
            for line in lines[-3:]:  # Show last 3 lines
                print(f"   {line}")
        
        return True
    
    return False

# Example library usage functions
def get_certificate_as_string(hostname, port=443):
    """
    Convenience function to get root certificate as string without saving to file
    
    Args:
        hostname (str): Target hostname
        port (int): Target port (default 443)
        
    Returns:
        str: Root certificate in PEM format, or None if failed
        
    Example:
        cert = get_certificate_as_string("internal.company.com", 443)
        if cert:
            print("Got certificate!")
    """
    # Try Python 3.13+ method first
    if sys.version_info >= (3, 13):
        cert = extract_root_cert_builtin(hostname, port)
        if cert:
            return cert
    
    # Fall back to OpenSSL
    return extract_root_cert_openssl(hostname, port)

def batch_extract_certificates(targets, output_dir="."):
    """
    Extract root certificates from multiple targets
    
    Args:
        targets (list): List of "hostname" or "hostname:port" strings
        output_dir (str): Directory to save certificates (default current directory)
        
    Returns:
        dict: {target: success_boolean} mapping
        
    Example:
        results = batch_extract_certificates([
            "site1.company.com", 
            "site2.company.com:8443", 
            "site3.company.com"
        ])
        for target, success in results.items():
            print(f"{target}: {'✅' if success else '❌'}")
    """
    import os
    results = {}
    
    for target in targets:
        print(f"\n{'='*20} {target} {'='*20}")
        hostname, port = parse_target(target)
        
        cert = get_certificate_as_string(hostname, port)
        if cert:
            filename = os.path.join(output_dir, f"{hostname}_root.crt")
            success = save_certificate(cert, filename)
            results[target] = success
        else:
            results[target] = False
    
    return results

# ============================================================================
# COMMAND LINE INTERFACE (when run as script)
# ============================================================================

if __name__ == "__main__":
    print("🔐 ROOT CERTIFICATE EXTRACTOR")
    print("=" * 35)
    
    if len(sys.argv) != 2:
        print("Usage: python extract_cert.py hostname:port")
        print("Example: python extract_cert.py abc.estsecurity.com:1234")
        print("Example: python extract_cert.py internal.company.com")
        print("\nNote: Built-in SSL support requires Python 3.13+")
        print("      For older versions, uses OpenSSL command (recommended anyway)")
        print("\n💡 Library usage: See docstring at top of file for import examples")
        sys.exit(1)
    
    target = sys.argv[1]
    success = extract_root_certificate(target)
    
    if not success:
        print("\n💡 Manual alternative:")
        hostname, port = parse_target(target)
        print(f"   openssl s_client -showcerts -servername {hostname} -connect {hostname}:{port}")
        print("   Then copy the last certificate block (-----BEGIN to -----END)")
        sys.exit(1)
