from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import open_reverselab_codex_support as support

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


def print_json(payload: dict) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if payload.get("overall") == "NEEDS_CONFIRMATION" or payload.get("requires_confirmation"):
        return 2
    return 0 if payload.get("overall") not in {"FAIL"} and payload.get("error") is None else 1


def resolve_project_path(value: str) -> Path:
    return support.normalize_project_root(value)


def command_install(args: argparse.Namespace) -> int:
    payload = support.install_or_repair_global_config(
        replace_related=args.replace_related,
        confirm_project_upgrades=args.confirm_project_upgrades,
    )
    return print_json(payload)


def command_uninstall(args: argparse.Namespace) -> int:
    payload = support.uninstall_global_config()
    return print_json(payload)


def command_status(args: argparse.Namespace) -> int:
    payload = support.codex_status_summary()
    return print_json(payload)


def command_bind(args: argparse.Namespace) -> int:
    payload = support.enable_project_mode(args.project_root, confirm=args.confirm_text)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload.get("ok") else 2 if payload.get("requires_confirmation") else 1


def command_unbind(args: argparse.Namespace) -> int:
    payload = support.disable_project_mode(args.project_root, confirm=args.confirm_text)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload.get("ok") else 2 if payload.get("requires_confirmation") else 1


def command_project_status(args: argparse.Namespace) -> int:
    payload = support.project_mode_status(args.project_root)
    return print_json(payload)


def command_project_repair(args: argparse.Namespace) -> int:
    payload = support.repair_project_mode(args.project_root, confirm=args.confirm_text)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload.get("ok") else 2 if payload.get("requires_confirmation") else 1


def command_backup_list(args: argparse.Namespace) -> int:
    payload = {
        "schema": 1,
        "generated_at": support.utc_now_iso(),
        "backups": support.list_backups(),
    }
    return print_json(payload)


def command_backup_restore(args: argparse.Namespace) -> int:
    payload = support.restore_backup(args.backup_id)
    return print_json(payload)


def command_upgrade_batch_list(args: argparse.Namespace) -> int:
    payload = {
        "schema": 1,
        "adapter_schema": support.ADAPTER_SCHEMA,
        "adapter_version": support.ADAPTER_VERSION,
        "generated_at": support.utc_now_iso(),
        "batches": support.list_upgrade_batches(),
    }
    return print_json(payload)


def command_upgrade_batch_restore(args: argparse.Namespace) -> int:
    payload = support.restore_upgrade_batch_project(args.batch_id, args.project_id)
    return print_json(payload)


def command_doctor(args: argparse.Namespace) -> int:
    payload = support.doctor()
    return print_json(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="open-reverselab Codex local manager")
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install", help="Install or repair global Codex integration")
    install.add_argument("--replace-related", action="store_true", help="Replace older related MCP entries that match this repo by path evidence")
    install.add_argument("--confirm-project-upgrades", action="store_true", help="Confirm batch upgrade of registered public-version projects")
    install.set_defaults(func=command_install)

    uninstall = sub.add_parser("uninstall", help="Remove global Codex integration")
    uninstall.set_defaults(func=command_uninstall)

    status = sub.add_parser("status", help="Show global adapter status")
    status.set_defaults(func=command_status)

    bind = sub.add_parser("bind-project", help="Bind another project to open-reverselab Codex mode")
    bind.add_argument("project_root")
    bind.add_argument("--confirm-text", default="")
    bind.set_defaults(func=command_bind)

    unbind = sub.add_parser("unbind-project", help="Unbind a project from open-reverselab Codex mode")
    unbind.add_argument("project_root")
    unbind.add_argument("--confirm-text", default="")
    unbind.set_defaults(func=command_unbind)

    project_status = sub.add_parser("project-status", help="Show project binding status")
    project_status.add_argument("project_root")
    project_status.set_defaults(func=command_project_status)

    repair = sub.add_parser("repair-project", help="Repair a bound project")
    repair.add_argument("project_root")
    repair.add_argument("--confirm-text", default="")
    repair.set_defaults(func=command_project_repair)

    backup_list = sub.add_parser("backup-list", help="List local adapter backups")
    backup_list.set_defaults(func=command_backup_list)

    backup_restore = sub.add_parser("backup-restore", help="Restore a local adapter backup")
    backup_restore.add_argument("backup_id")
    backup_restore.set_defaults(func=command_backup_restore)

    upgrade_batch_list = sub.add_parser("upgrade-batch-list", help="List recorded project upgrade batches")
    upgrade_batch_list.set_defaults(func=command_upgrade_batch_list)

    upgrade_batch_restore = sub.add_parser("upgrade-batch-restore", help="Restore one project from an upgrade batch")
    upgrade_batch_restore.add_argument("batch_id")
    upgrade_batch_restore.add_argument("project_id")
    upgrade_batch_restore.set_defaults(func=command_upgrade_batch_restore)

    doctor = sub.add_parser("doctor", help="Verify wrapper and adapter status")
    doctor.set_defaults(func=command_doctor)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
