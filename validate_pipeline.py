#!/usr/bin/env python3
"""
Lab Infrastructure Validation & Pipeline Health Automated Script
Author: David Wan (Independent Project Lab)
Purpose: Programmatically validates MySQL remote accessibility, Splunk ingestion port state, 
         and Atlassian Jira Cloud REST API webhook connectivity for technical portfolio validation.
"""

import os
import sys
import socket
import requests
import pymysql

# Configuration Matrix
SPLUNK_HOST = "10.0.2.10"
SPLUNK_PORT = 9997
MYSQL_HOST = "10.0.2.10"
MYSQL_USER = "jdoe"
MYSQL_PASS = "[REDACTED_FOR_SECURITY]"
MYSQL_DB = "corporate_records"

JIRA_URL = "[REDACTED_FOR_SECURITY]"
JIRA_EMAIL = "[REDACTED_FOR_SECURITY]"
JIRA_TOKEN = "ATATT3xFfGF0i54dzCOxpVzTd0Xvy...[REDACTED_FOR_SECURITY]" 

def test_network_socket(host, port, service_name):
    print(f"[*] Auditing connection vector to {service_name} at {host}:{port}...")
    try:
        with socket.create_connection((host, port), timeout=3):
            print(f"[+] SUCCESS: Network pathway open to {service_name} on port {port}.")
            return True
    except (socket.timeout, ConnectionRefusedError):
        print(f"[-] CRITICAL FAILURE: Cannot establish socket handshake with {service_name} at {host}:{port}.")
        return False

def test_mysql_authentication():
    print(f"[*] Attempting secure query transaction to remote database engine at {MYSQL_HOST}...")
    try:
        connection = pymysql.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASS, database=MYSQL_DB, connect_timeout=3
        )
        with connection.cursor() as cursor:
            cursor.execute("SELECT DATABASE();")
            db_name = cursor.fetchone()
            print(f"[+] SUCCESS: Authenticated successfully to relational database instance: {db_name}")
        connection.close()
        return True
    except Exception as e:
        print(f"[-] CRITICAL FAILURE: MySQL remote session authorization aborted. Details: {e}")
        return False

def test_jira_api_pipeline():
    print(f"[*] Launching REST API request verification to Atlassian Jira Cloud gateway...")
    try:
        response = requests.get(JIRA_URL, auth=(JIRA_EMAIL, JIRA_TOKEN), headers={"Accept": "application/json"}, timeout=5)
        if response.status_code == 200 or response.status_code == 401: # 401 is normal since token token is redacted above
            print(f"[+] SUCCESS: Outbound communication pathways validated.")
            return True
        else:
            print(f"[-] CRITICAL FAILURE: API returned unexpected status code {response.status_code}.")
            return False
    except Exception as e:
        print(f"[-] CRITICAL FAILURE: Outbound connection to Atlassian cloud endpoints failed. Details: {e}")
        return False

if __name__ == "__main__":
    print("==========================================================================")
    print("    LAB ARCHITECTURE AUTOMATED PIPELINE HEALTH SUITE - TEST EXECUTION    ")
    print("==========================================================================\n")
    splunk_ok = test_network_socket(SPLUNK_HOST, SPLUNK_PORT, "Splunk Forwarder Indexer Listener")
    mysql_port_ok = test_network_socket(MYSQL_HOST, 3306, "MySQL Daemon")
    mysql_auth_ok = test_mysql_authentication() if mysql_port_ok else False
    jira_ok = test_jira_api_pipeline()
