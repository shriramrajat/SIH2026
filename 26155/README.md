# SIH 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

## Problem Statement

**PS ID:** SIH26155

**Organization:** National Technical Research Organisation (NTRO)

**Category:** Software

**Theme:** Blockchain & Cybersecurity

## POC Objective

Prove that configuration files from different network vendors can be converted
into a common vendor-neutral security representation.

## POC Scope

The first POC will support:

- Cisco configuration
- Juniper configuration

The first security controls will be:

1. SSH protocol version
2. Telnet status
3. Administrative/session security

## Expected Flow

Configuration File
        ↓
Vendor Detection
        ↓
Configuration Parsing
        ↓
Security Control Extraction
        ↓
Vendor-Neutral Schema
        ↓
Compliance Result

## Success Criteria

The POC is successful if:

1. Cisco configuration can be parsed.
2. Juniper configuration can be parsed.
3. Both produce the same normalized schema.
4. At least three security controls can be extracted.
5. Unknown configuration syntax is detected instead of silently ignored.

## Current Status

POC development — Not Started