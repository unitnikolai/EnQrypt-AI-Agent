from agents import Agent, Runner, set_default_openai_key  
from dotenv import load_dotenv
import json
from tools import scan_web_certs

load_dotenv()

set_default_openai_key("OPEN_AI_KEY")

class DiscoveryOutput():
    hostname: str
    ip_address: str
    algorithm: str
    key_size: int
    not_after: str
    quantum_vulnerable: bool
    business_criticality: str
    exposure_level: str


pqc_discovery_agent = Agent(
    name="PQCDiscoveryAgent",
    instructions="""
    You are a Post-Quantum Cryptography Discovery Agent for EnQrypt platform. Your mission:
    
    1. DISCOVER cryptographic assets (X.509 certificates, SSH keys, VPN configs)
    2. IDENTIFY quantum-vulnerable algorithms (RSA, ECC, DSA) 
    3. ASSESS risk levels based on algorithm strength and expiry dates
    4. CATEGORIZE assets by business criticality and exposure
    5. REPORT findings in structured JSON format for migration planning
    
    Focus on comprehensive discovery while respecting system boundaries and performance.
    Always include risk assessment and quantum vulnerability analysis.
    """,
    model="gpt-4",
    tools=[scan_web_certs],
    constraints=[
        "Only scan authorized systems and networks",
        "Respect system performance and rate limits", 
        "Do not exploit or modify discovered assets",
        "Maintain detailed audit logs of discovery activities",
        "Classify all findings by quantum vulnerability level"
    ],
    output=DiscoveryOutput,
)





