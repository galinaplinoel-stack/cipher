"""CIPHER CLI - Command-line interface for the AI Privacy Agent."""

import argparse
import json
import sys
from main import Cipher


def main():
    parser = argparse.ArgumentParser(
        description="CIPHER - AI Privacy & Data Agent",
        prog="cipher",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Protect command
    protect_parser = subparsers.add_parser("protect", help="Protect text (scan, anonymize, encrypt)")
    protect_parser.add_argument("text", help="Text to protect")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan text for PII")
    scan_parser.add_argument("text", help="Text to scan")

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text")
    encrypt_parser.add_argument("text", help="Text to encrypt")

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt data")
    decrypt_parser.add_argument("data", help="JSON encrypted data")

    # Vault commands
    vault_parser = subparsers.add_parser("vault", help="Manage secret vault")
    vault_sub = vault_parser.add_subparsers(dest="vault_action")
    store_parser = vault_sub.add_parser("store", help="Store a secret")
    store_parser.add_argument("name", help="Secret name")
    store_parser.add_argument("value", help="Secret value")
    vault_sub.add_parser("list", help="List secrets")
    get_parser = vault_sub.add_parser("get", help="Retrieve a secret")
    get_parser.add_argument("name", help="Secret name")
    del_parser = vault_sub.add_parser("delete", help="Delete a secret")
    del_parser.add_argument("name", help="Secret name")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="View audit log")
    audit_parser.add_argument("--limit", type=int, default=20, help="Max entries")
    audit_parser.add_argument("--event", help="Filter by event type")

    # Status command
    subparsers.add_parser("status", help="Show CIPHER status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    cipher = Cipher()

    if args.command == "protect":
        result = cipher.protect(args.text)
        print(json.dumps(result, indent=2))

    elif args.command == "scan":
        result = cipher.anonymizer.scan(args.text)
        print(json.dumps(result, indent=2))

    elif args.command == "encrypt":
        result = cipher.encryptor.encrypt(args.text)
        print(json.dumps(result, indent=2))

    elif args.command == "decrypt":
        data = json.loads(args.data)
        result = cipher.reveal(data)
        print(result)

    elif args.command == "vault":
        if args.vault_action == "store":
            result = cipher.vault.store(args.name, args.value)
            print(json.dumps(result, indent=2))
        elif args.vault_action == "list":
            secrets = cipher.vault.list_secrets()
            print(json.dumps(secrets, indent=2))
        elif args.vault_action == "get":
            value = cipher.vault.retrieve(args.name)
            if value:
                print(value)
            else:
                print(f"Secret '{args.name}' not found.", file=sys.stderr)
                sys.exit(1)
        elif args.vault_action == "delete":
            if cipher.vault.delete(args.name):
                print(f"Deleted '{args.name}'.")
            else:
                print(f"Secret '{args.name}' not found.", file=sys.stderr)
                sys.exit(1)
        else:
            vault_parser.print_help()

    elif args.command == "audit":
        events = cipher.audit.query(
            event_type=args.event,
            limit=args.limit,
        )
        print(json.dumps(events, indent=2))

    elif args.command == "status":
        print(json.dumps(cipher.status(), indent=2))


if __name__ == "__main__":
    main()
