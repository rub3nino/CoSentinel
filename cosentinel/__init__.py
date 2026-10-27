"""Cosentinel — a local, SSH-based security posture & hardening orchestrator.

It runs on your machine, connects to the machines you own over SSH, orchestrates
established scanners (Lynis from inside, Nmap/Nuclei from outside), normalizes
everything into one finding model, and keeps history locally. No always-on
service, nothing exposed to the internet.
"""

__version__ = "0.2.0"
