
import os
import ssl
import json
from typing import List, Dict, Any
import socket
import requests
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519


def is_pqc_compliant(cert_der: bytes) -> bool:
    
    return False

def _is_quantum_vulnerable(algorithm: str, key_size: int) -> bool:
    """Determines if crypto alg is vulnerable to quantum attacks"""
    vulnerable_algorithms ={
        "RSA": True,
        "ECC": True,
        "DSA": True,
        "ECDSA": True,
    }

    pq_resistant = ["kyber", "falcon", "sphincs","dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024", "rainbowi-classic", "rainbowiii-cyclic"]

    if algorithm.lower() in [alg.lower() for alg in pq_resistant]:
        return False
    return vulnerable_algorithms.get(algorithm.upper(), True)


def _get_ai_cert_analysis(cert_info: Dict[str, Any]) -> Dict[str, Any]:
    AI_ANALYSIS_AVAILABLE = True
    

    
def _assess_security_level(algorithm: str, key_size: int) -> str:
    """Assess the current security level of the crypto algorithm"""
    if algorithm == "RSA":
        if key_size >= 3072:
            return "high"
        elif key_size >= 2048:
            return "medium"
        elif key_size >= 1024:
            return "low"
        else:
            return "unknown"
    elif algorithm == "ECC":
        if key_size >= 384:
            return "high"
        elif key_size >= 256:
            return "medium"
        elif key_size >= 160:
            return "low"
        elif algorithm in ["dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024", "rainbowi-classic", "rainbowiii-cyclic"]:
            return "post-quantum safe"
        elif algorithm in ["Ed25519", "Ed448"]:
            return "high"
        else:
            return "unknown"



def scan_web_certs(hostname: str, ip_addr=None, port: int = 443) -> Dict[str, Any]:
    try:
        destination = ip_addr if (ip_addr and not hostname) else hostname 
        tls_context = ssl.create_default_context()
        with socket.create_connection((destination, port), timeout=15) as sock:
            with tls_context.wrap_socket(sock, server_hostname=destination) as ssock:                    
                cert_der = ssock.getpeercert(binary_form=True)
                cert_info = ssock.getpeercert()
                return {
                    "hostname": hostname, 
                    "ip_address": ip_addr if ip_addr else socket.gethostbyname(hostname),
                    "port": port,                         "subject": dict(x[0] for x in cert_info['subject']),
                    "issuer": dict(x[0] for x in cert_info['issuer']),
                    "version": cert_info.get('version'),
                    "serialNumber": cert_info.get('serialNumber'),
                    "not_before": cert_info.get('notBefore'),                        
                    "not_after": cert_info.get('notAfter'),
                    "public_key_algorithm": cert_info.get('subjectPublicKeyInfo', {}).get('algorithm'),
                    "pqc_compliant": is_pqc_compliant(cert_der),                    }
    
    except ssl.SSLError as e:
        return {"error": f"SSL error while scanning {hostname}:{port} - {str(e)}"}
    except socket.gaierror as e:
        return {"error": f"DNS resolution failed for {hostname} - {str(e)}"}
    except Exception as e:
        return {"error": f"Failed to scan {hostname}:{port} - {str(e)}"}

def _analyze_certificate_crypto(cert_der: bytes) -> Dict[str, Any]:
    try:
        cert_obj = x509.load_der_x509_certificate(cert_der)
        pub_key = cert_obj.public_key()
        key_info = _get_key_algorithm_details(pub_key)
        signature_algorithm = cert_obj.signature_algorithm_oid._name
        quantum_vulnerable = _is_quantum_vulnerable(key_info["algorithm"], key_info.get("key_size", 0))
        security_level = _assess_security_level(key_info["algorithm"], key_info.get("key_size", 0))
        return {
            "public_key_algorithm": key_info["algorithm"],
            "public_key_size": key_info.get("key_size"),
            "signature_algorithm": signature_algorithm,
            "quantum_vulnerable": quantum_vulnerable,
            "security_level": security_level,
            "key_details": key_info,
            "pqc_ready": key_info["algorithm"].lower() in ["dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024", "rainbowi-classic", "rainbowiii-cyclic"],
            "migration_priority": "high" if quantum_vulnerable and security_level in ["low", "medium"] else "medium"
        }
    except Exception as e:
        return {"error": f"Failed to analyze certificate - {str(e)}"}

def _get_key_algorithm_details(pub_key) -> Dict[str, Any]:
    """Extract detailed information about the pub key algorithm."""
    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            return {
                "algorithm": "RSA",
                "key_size": pub_key.key_size,
                "exponent": pub_key.public_numbers().e,
                "modulus_size": pub_key.key_size,
                "details": f"RSA key with size {pub_key.key_size} with exponent {pub_key.public_numbers().e}"
            }
        elif isinstance(pub_key, x509.EllipticCurvePublicKey):
            curve_name = pub_key.curve.name.lower()
            return {
                "algorithm": "ECDSA",
                "key_size": pub_key.curve.key_size,
                "curve": curve_name,
                "curve_type": type(pub_key.curve).__name__,
                "details": f"ECC with {curve_name} curve ({pub_key.curve.key_size} bit)"
            }
        elif isinstance(pub_key, x509.DSAPublicKey):
            return {
                "algorithm": "DSA",
                "key_size": pub_key.key_size,
                "details": f"DSA key with size {pub_key.key_size}"
            }
        elif isinstance(pub_key, x509.Ed25519PublicKey):
            return {
                "algorithm": "Ed25519",
                "key_size": 256
            }
        else:
            return {
                "algorithm": "Unknown",
                "key_size": None
            }
    except Exception as e:
        return {
            "algorithm": "Unknown",
            "key_size": None,
            "error": f"Failed to extract key details - {str(e)}"
        }


def scan_file_system_certs(path: str) -> List[Dict[str, Any]]:    
    cert_exentensions = ['.crt', '.pem', '.der', '.cer', 'pfx', '.p12']    
    certificates = []
    try:
        for root, dirs, files in os.walk(path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in cert_exentensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as f:
                            cert_data = f.read()
                            try:
                                cert = ssl.DER_cert_to_PEM_cert(cert_data)
                            except ValueError:
                                cert = cert_data.decode('utf-8', errors='ignore')
                            certificates.append({
                                "file_path": file_path,
                                "certificate": cert,
                                "modified_data" : datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                                "pqc_compliant": is_pqc_compliant(cert_data)
                            })
                    except Exception as e:
                        certificates.append({
                            "file_path": file_path,
                            "error": f"Failed to read certificate - {str(e)}"
                        })
    except PermissionError:
        return [{"error": "Permission denied while accessing the filesystem"}]
        
    return certificates

def scan_network_range(cidr: str, ports: List[int] = [443, 22, 6443, 8200, 8443, 3000, 8080, 993, 995, 465, 587, 3306, 5432, 1433, 27017, 6380, 6443, 2376, 10250, 3389]) -> List[Dict[str, Any]]:
    """Scan network range for services for crypto"""
    discovered_services = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            ip_str = str(ip)
            for port in ports:
                try:
                    with socket.create_connection((ip_str, port), timeout=3):
                        discovered_services.append({
                            "ip_address": ip_str,
                            "port": port,
                            "status": "open"
                        })
                except (socket.timeout, ConnectionRefusedError):
                    continue
                except Exception as e:
                    discovered_services.append({
                        "ip_address": ip_str,
                        "port": port,
                        "error": str(e),
                        "status": "open",
                        "potential_crypto_service": True,
                        "discovery_timestamp": datetime.now().isoformat(),
                    })
    except Exception as e:
        return [{"error": f"Failed to scan network range {cidr} - {str(e)}"}]