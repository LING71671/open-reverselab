# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=1.2.0,<2",
#     "pycryptodome>=3.20.0,<4",
# ]
# ///

from __future__ import annotations

import argparse
import json
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from reverselab_mcp.config import REVERSE_ROOT, SERVER_NAME
from reverselab_mcp.paths import resolve_file
from reverselab_mcp.tools import (
    android_mumu,
    analysis_notes,
    crypto_unpack,
    debug_scripts,
    ghidra_headless,
    ghidra_summary,
    ioc_extract,
    mcp_update,
    mutations,
    patch_reports,
    procmon_filters,
    python_re_tools,
    rizin_write,
    sample_crud,
    sigma_stub,
    toolbox,
    triage,
    unpack_intake,
    web_ctf,
    workflow,
    workspace_crud,
    yara_stub,
)


mcp = FastMCP(SERVER_NAME)


def _safe_call(func: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def hash_file(path: str) -> dict[str, Any]:
    """计算文件 MD5/SHA1/SHA256 和大小。"""
    return _safe_call(triage.hash_file, path)


@mcp.tool()
def die_scan(path: str, deep: bool = False, heuristic: bool = False, entropy: bool = False) -> dict[str, Any]:
    """使用 DiE/diec 扫描文件类型、编译器、packer/signature。默认 JSON 输出。"""
    return _safe_call(triage.die_scan, path, deep, heuristic, entropy)


@mcp.tool()
def rizin_bin_info(path: str) -> dict[str, Any]:
    """使用 rz-bin -j -I 输出二进制基础信息。"""
    return _safe_call(triage.rizin_bin_info, path)


@mcp.tool()
def rizin_sections(path: str) -> dict[str, Any]:
    """使用 rz-bin -j -S 输出节区信息。"""
    return _safe_call(triage.rizin_sections, path)


@mcp.tool()
def rizin_imports(path: str, limit: int = 300) -> dict[str, Any]:
    """使用 rz-bin -j -i 输出导入表，可限制返回数量。"""
    return _safe_call(triage.rizin_imports, path, limit)


@mcp.tool()
def rizin_strings(path: str, limit: int = 300) -> dict[str, Any]:
    """使用 rz-bin -zz 输出 raw strings 文本行，可限制返回数量。"""
    return _safe_call(triage.rizin_strings, path, limit)


@mcp.tool()
def triage_pe(path: str, write_markdown: bool = False) -> dict[str, Any]:
    """组合 hash、DiE、rz-bin info/sections/imports/strings，生成只读初筛结果。"""
    return _safe_call(triage.triage_pe, path, write_markdown)


@mcp.tool()
def ghidra_headless_analyze(
    path: str,
    project_name: str = "",
    overwrite: bool = True,
    analysis_timeout_seconds: int = 600,
    process_timeout_seconds: int = 1800,
    function_limit: int = 300,
    string_limit: int = 300,
    import_limit: int = 300,
) -> dict[str, Any]:
    """调用 Ghidra analyzeHeadless 导入并自动分析样本，导出 JSON 摘要；不执行样本。"""
    return _safe_call(
        ghidra_headless.ghidra_headless_analyze,
        path,
        project_name,
        overwrite,
        analysis_timeout_seconds,
        process_timeout_seconds,
        function_limit,
        string_limit,
        import_limit,
    )


@mcp.tool()
def ghidra_summary_list(limit: int = 20) -> dict[str, Any]:
    """列出 exports\\windows\\ghidra 下已导出的 Ghidra summary JSON。"""
    return _safe_call(ghidra_summary.ghidra_summary_list, limit)


@mcp.tool()
def ghidra_summary_overview(summary_path: str = "") -> dict[str, Any]:
    """读取 Ghidra summary 的总体信息，不返回完整 functions/imports/strings。"""
    return _safe_call(ghidra_summary.ghidra_summary_overview, summary_path)


@mcp.tool()
def ghidra_summary_functions(summary_path: str = "", query: str = "", address: str = "", limit: int = 50) -> dict[str, Any]:
    """从已导出的 Ghidra summary 中按函数名、signature 或地址过滤 functions。"""
    return _safe_call(ghidra_summary.ghidra_summary_functions, summary_path, query, address, limit)


@mcp.tool()
def ghidra_summary_function_detail(
    summary_path: str = "",
    address: str = "",
    name: str = "",
    include_decompile: bool = True,
    max_decompile_chars: int = 12000,
) -> dict[str, Any]:
    """按地址或函数名读取单个 Ghidra 函数的 callers/callees/import_refs/string_refs/decompile 证据。"""
    return _safe_call(ghidra_summary.ghidra_summary_function_detail, summary_path, address, name, include_decompile, max_decompile_chars)


@mcp.tool()
def ghidra_summary_imports(
    summary_path: str = "",
    query: str = "",
    library: str = "",
    min_refs: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """从已导出的 Ghidra summary 中按 API 名、namespace/library、引用数过滤 imports。"""
    return _safe_call(ghidra_summary.ghidra_summary_imports, summary_path, query, library, min_refs, limit)


@mcp.tool()
def ghidra_summary_strings(
    summary_path: str = "",
    query: str = "",
    min_length: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """从已导出的 Ghidra summary 中按字符串内容、地址、最小长度过滤 strings。"""
    return _safe_call(ghidra_summary.ghidra_summary_strings, summary_path, query, min_length, limit)


@mcp.tool()
def ghidra_summary_call_focus(
    summary_path: str = "",
    query: str = "",
    behavior: str = "",
    min_body_size: int = 32,
    limit: int = 12,
) -> dict[str, Any]:
    """基于 Ghidra xrefs/calls/decompile/imports/strings 给出函数阅读优先级；兼容 legacy summary。"""
    return _safe_call(ghidra_summary.ghidra_summary_call_focus, summary_path, query, behavior, min_body_size, limit)


@mcp.tool()
def copy_sample_to_patches(path: str, case_name: str = "", output_name: str = "", overwrite: bool = False) -> dict[str, Any]:
    """复制样本到 patches 目录，原始样本不变，并写入 audit log。"""
    return _safe_call(mutations.copy_sample_to_patches, path, case_name, output_name, overwrite)


@mcp.tool()
def patch_bytes(
    path: str,
    offset: int,
    new_bytes_hex: str,
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
) -> dict[str, Any]:
    """复制输入文件到 patches 后修改指定 offset 的字节；不原地修改样本。"""
    return _safe_call(mutations.patch_bytes, path, offset, new_bytes_hex, output_path, case_name, overwrite)


@mcp.tool()
def pe_address_to_offset(path: str, address: str, address_type: str = "auto") -> dict[str, Any]:
    """将 PE 的 file offset/RVA/VA 映射为文件偏移。"""
    return _safe_call(mutations.pe_address_to_offset, path, address, address_type)


@mcp.tool()
def patch_pe_bytes(
    path: str,
    address: str,
    new_bytes_hex: str,
    address_type: str = "auto",
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
) -> dict[str, Any]:
    """按 PE file offset/RVA/VA 定位后 patch 副本字节；不原地修改样本。"""
    return _safe_call(mutations.patch_pe_bytes, path, address, new_bytes_hex, address_type, output_path, case_name, overwrite)


@mcp.tool()
def search_pattern(path: str, pattern: str, start_offset: int = 0, max_matches: int = 50) -> dict[str, Any]:
    """按十六进制 pattern 搜索文件，支持 ?? 通配。"""
    return _safe_call(mutations.search_pattern, path, pattern, start_offset, max_matches)


@mcp.tool()
def patch_pattern(
    path: str,
    pattern: str,
    new_bytes_hex: str,
    occurrence: int = 0,
    require_unique: bool = False,
    start_offset: int = 0,
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
) -> dict[str, Any]:
    """按十六进制 pattern 定位后 patch 副本字节；pattern 支持 ?? 通配。"""
    return _safe_call(
        mutations.patch_pattern,
        path,
        pattern,
        new_bytes_hex,
        occurrence,
        require_unique,
        start_offset,
        output_path,
        case_name,
        overwrite,
    )


@mcp.tool()
def generate_patch_report(
    output_path: str = "",
    source_contains: str = "",
    destination_contains: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    """从 mutation audit log 生成 Markdown patch report。"""
    return _safe_call(patch_reports.generate_patch_report, output_path, source_contains, destination_contains, limit)


@mcp.tool()
def list_generated_artifacts(root: str = "patches", limit: int = 100) -> dict[str, Any]:
    """列出 exports/patches/projects/reports 中的工具生成物。"""
    return _safe_call(mutations.list_generated_artifacts, root, limit)


@mcp.tool()
def delete_generated_artifact(path: str, dry_run: bool = True) -> dict[str, Any]:
    """删除工具生成目录内的文件/目录；默认 dry_run=True。"""
    return _safe_call(mutations.delete_generated_artifact, path, dry_run)


@mcp.tool()
def mutation_audit_tail(limit: int = 50) -> dict[str, Any]:
    """读取 mutation audit log 尾部记录。"""
    return _safe_call(mutations.audit_tail, limit)


@mcp.tool()
def android_mumu_instance_info(serial: str = "") -> dict[str, Any]:
    """读取 MuMu 当前实例状态、候选 serial 和 adb 可达性。"""
    return _safe_call(android_mumu.android_mumu_instance_info, serial)


@mcp.tool()
def android_adb_connect(serial: str = "") -> dict[str, Any]:
    """连接 MuMu/Android ADB 端点；默认使用 MuMu 当前实例 serial。"""
    return _safe_call(android_mumu.android_adb_connect, serial)


@mcp.tool()
def android_adb_devices() -> dict[str, Any]:
    """列出当前 adb devices -l。"""
    return _safe_call(android_mumu.android_adb_devices)


@mcp.tool()
def android_device_info(serial: str = "") -> dict[str, Any]:
    """读取 Android 设备的 model/sdk/abi/fingerprint/root 状态。"""
    return _safe_call(android_mumu.android_device_info, serial)


@mcp.tool()
def android_list_packages(serial: str = "", query: str = "", limit: int = 200) -> dict[str, Any]:
    """列出 Android 包名，可按 query 过滤。"""
    return _safe_call(android_mumu.android_list_packages, serial, query, limit)


@mcp.tool()
def android_install_apk(apk_path: str, serial: str = "", reinstall: bool = True, grant_permissions: bool = False) -> dict[str, Any]:
    """通过 adb install 把 APK 装进 MuMu/Android 设备。"""
    return _safe_call(android_mumu.android_install_apk, apk_path, serial, reinstall, grant_permissions)


@mcp.tool()
def android_uninstall_package(package_name: str, serial: str = "", keep_data: bool = False) -> dict[str, Any]:
    """卸载 Android 包。"""
    return _safe_call(android_mumu.android_uninstall_package, package_name, serial, keep_data)


@mcp.tool()
def android_start_package(package_name: str, activity: str = "", serial: str = "") -> dict[str, Any]:
    """启动 Android app；未指定 activity 时走 monkey 启动默认入口。"""
    return _safe_call(android_mumu.android_start_package, package_name, activity, serial)


@mcp.tool()
def android_force_stop(package_name: str, serial: str = "") -> dict[str, Any]:
    """强制停止 Android app。"""
    return _safe_call(android_mumu.android_force_stop, package_name, serial)


@mcp.tool()
def android_logcat_dump(serial: str = "", output_path: str = "", clear_before: bool = False, max_lines: int = 2000) -> dict[str, Any]:
    """导出当前设备 logcat 到 exports\\android。"""
    return _safe_call(android_mumu.android_logcat_dump, serial, output_path, clear_before, max_lines)


@mcp.tool()
def android_clear_logcat(serial: str = "") -> dict[str, Any]:
    """清空当前设备 logcat 缓冲区。"""
    return _safe_call(android_mumu.android_clear_logcat, serial)


@mcp.tool()
def android_push_file(local_path: str, remote_path: str, serial: str = "") -> dict[str, Any]:
    """把本地文件推送到 Android 设备。"""
    return _safe_call(android_mumu.android_push_file, local_path, remote_path, serial)


@mcp.tool()
def android_pull_file(remote_path: str, serial: str = "", output_path: str = "") -> dict[str, Any]:
    """从 Android 设备拉取文件到 exports\\android。"""
    return _safe_call(android_mumu.android_pull_file, remote_path, serial, output_path)


@mcp.tool()
def android_current_activity(serial: str = "") -> dict[str, Any]:
    """读取当前前台 Activity。"""
    return _safe_call(android_mumu.android_current_activity, serial)


@mcp.tool()
def android_package_paths(package_name: str, serial: str = "") -> dict[str, Any]:
    """读取包对应的 base.apk / split APK 路径。"""
    return _safe_call(android_mumu.android_package_paths, package_name, serial)


@mcp.tool()
def android_pull_package_apk(package_name: str, serial: str = "") -> dict[str, Any]:
    """把设备上的包 APK 拉回 exports\\android\\packages。"""
    return _safe_call(android_mumu.android_pull_package_apk, package_name, serial)


@mcp.tool()
def android_capture_screenshot(serial: str = "", output_path: str = "") -> dict[str, Any]:
    """抓取当前设备屏幕截图。"""
    return _safe_call(android_mumu.android_capture_screenshot, serial, output_path)


@mcp.tool()
def android_package_info(package_name: str, serial: str = "", output_path: str = "") -> dict[str, Any]:
    """导出 dumpsys package 结果，便于分析权限、组件和安装状态。"""
    return _safe_call(android_mumu.android_package_info, package_name, serial, output_path)


@mcp.tool()
def android_frida_ensure_server(serial: str = "", version: str = "17.9.8", arch: str = "android-x86_64") -> dict[str, Any]:
    """在 MuMu/Android root 设备上部署并启动 frida-server。"""
    return _safe_call(android_mumu.android_frida_ensure_server, serial, version, arch)


@mcp.tool()
def android_frida_status(serial: str = "") -> dict[str, Any]:
    """检查 frida-server 进程和桌面端 Frida 是否能枚举该设备。"""
    return _safe_call(android_mumu.android_frida_status, serial)


@mcp.tool()
def android_frida_processes(serial: str = "", query: str = "", limit: int = 50) -> dict[str, Any]:
    """通过桌面端 Frida 枚举 Android 设备进程。"""
    return _safe_call(android_mumu.android_frida_processes, serial, query, limit)


@mcp.tool()
def android_frida_run_script(
    target: str,
    script_source: str,
    serial: str = "",
    mode: str = "attach",
    duration_seconds: int = 10,
    output_path: str = "",
) -> dict[str, Any]:
    """对指定进程/包运行一次性 Frida JS 脚本，收集 send() 消息并导出 JSON。"""
    return _safe_call(android_mumu.android_frida_run_script, target, script_source, serial, mode, duration_seconds, output_path)


@mcp.tool()
def android_frida_template_library() -> dict[str, Any]:
    """列出可直接复用的 Frida JS 模板。"""
    return _safe_call(android_mumu.android_frida_template_library)


@mcp.tool()
def android_frida_render_template(template_id: str, substitutions_json: str = "") -> dict[str, Any]:
    """渲染 Frida 模板为可直接运行的 JS 源码。"""
    return _safe_call(android_mumu.android_frida_render_template, template_id, substitutions_json)


@mcp.tool()
def android_app_baseline(
    package_name: str = "",
    apk_path: str = "",
    serial: str = "",
    reinstall: bool = False,
    grant_permissions: bool = False,
    launch: bool = True,
    clear_logcat_first: bool = True,
    logcat_lines: int = 400,
    output_path: str = "",
) -> dict[str, Any]:
    """安装/启动 APK 或已装包，收集 Activity、APK 路径、package info、logcat、Frida 进程基线。"""
    return _safe_call(
        android_mumu.android_app_baseline,
        package_name,
        apk_path,
        serial,
        reinstall,
        grant_permissions,
        launch,
        clear_logcat_first,
        logcat_lines,
        output_path,
    )


@mcp.tool()
def android_pull_artifact_recipe(
    package_name: str,
    serial: str = "",
    include_apk: bool = True,
    include_screenshot: bool = True,
    include_package_info: bool = True,
    include_logcat: bool = True,
    max_logcat_lines: int = 400,
    output_path: str = "",
) -> dict[str, Any]:
    """按包名回拉 APK、截图、包信息、logcat，并写出一份 artifact manifest。"""
    return _safe_call(
        android_mumu.android_pull_artifact_recipe,
        package_name,
        serial,
        include_apk,
        include_screenshot,
        include_package_info,
        include_logcat,
        max_logcat_lines,
        output_path,
    )


@mcp.tool()
def android_package_fs_recipe(
    package_name: str,
    serial: str = "",
    include_archives: bool = True,
    subdirs_csv: str = "shared_prefs,databases,files",
    max_depth: int = 2,
    max_entries: int = 200,
    output_path: str = "",
) -> dict[str, Any]:
    """按包名取证私有目录，列结构并按需回拉 shared_prefs/databases/files 归档。"""
    return _safe_call(
        android_mumu.android_package_fs_recipe,
        package_name,
        serial,
        include_archives,
        subdirs_csv,
        max_depth,
        max_entries,
        output_path,
    )


@mcp.tool()
def android_runtime_file_watch_recipe(
    package_name: str,
    serial: str = "",
    launch: bool = True,
    observe_seconds: int = 3,
    subdirs_csv: str = "shared_prefs,databases,files",
    max_depth: int = 2,
    max_entries: int = 200,
    output_path: str = "",
) -> dict[str, Any]:
    """对包目录做运行前后快照，输出 shared_prefs/databases/files 的差异清单。"""
    return _safe_call(
        android_mumu.android_runtime_file_watch_recipe,
        package_name,
        serial,
        launch,
        observe_seconds,
        subdirs_csv,
        max_depth,
        max_entries,
        output_path,
    )


@mcp.tool()
def android_http_observation_recipe(
    package_name: str,
    serial: str = "",
    target_process: str = "",
    launch: bool = False,
    observe_seconds: int = 8,
    clear_logcat_first: bool = False,
    logcat_lines: int = 800,
    template_ids_csv: str = "webview_navigation,webview_js_bridge,okhttp_newcall,okhttp_response",
    output_path: str = "",
) -> dict[str, Any]:
    """对已登录/已安装 Android 包做 HTTP/WebView/OkHttp 运行时观察，输出 Frida + logcat 证据汇总。"""
    return _safe_call(
        android_mumu.android_http_observation_recipe,
        package_name,
        serial,
        target_process,
        launch,
        observe_seconds,
        clear_logcat_first,
        logcat_lines,
        template_ids_csv,
        output_path,
    )


@mcp.tool()
def android_crypto_unpack_recipe(
    package_name: str,
    serial: str = "",
    target_process: str = "",
    launch: bool = False,
    observe_seconds: int = 10,
    clear_logcat_first: bool = False,
    logcat_lines: int = 1000,
    template_ids_csv: str = android_mumu.ANDROID_CRYPTO_UNPACK_TEMPLATES,
    output_path: str = "",
) -> dict[str, Any]:
    """Android 解密/去壳 runtime recipe：Frida 抓 Cipher/key/iv/hash/dex loader/dlopen/mmap/RegisterNatives。"""
    return _safe_call(
        android_mumu.android_crypto_unpack_recipe,
        package_name,
        serial,
        target_process,
        launch,
        observe_seconds,
        clear_logcat_first,
        logcat_lines,
        template_ids_csv,
        output_path,
    )


@mcp.tool()
def import_sample(
    source_path: str,
    destination_name: str = "",
    destination_subdir: str = "",
    overwrite: bool = False,
    move_source: bool = False,
) -> dict[str, Any]:
    """导入文件到 samples，可选 move；适合把外部样本纳入工作台。"""
    return _safe_call(sample_crud.import_sample, source_path, destination_name, destination_subdir, overwrite, move_source)


@mcp.tool()
def list_samples(limit: int = 200, subdir: str = "") -> dict[str, Any]:
    """列出 samples 下样本，可按子目录过滤。"""
    return _safe_call(sample_crud.list_samples, limit, subdir)


@mcp.tool()
def rename_sample(path: str, new_name: str, overwrite: bool = False) -> dict[str, Any]:
    """重命名 samples 下的样本文件。"""
    return _safe_call(sample_crud.rename_sample, path, new_name, overwrite)


@mcp.tool()
def copy_sample(path: str, destination_name: str = "", destination_subdir: str = "", overwrite: bool = False) -> dict[str, Any]:
    """复制 samples 下的样本到另一个 samples 位置。"""
    return _safe_call(sample_crud.copy_sample, path, destination_name, destination_subdir, overwrite)


@mcp.tool()
def move_sample(path: str, destination_name: str = "", destination_subdir: str = "", overwrite: bool = False) -> dict[str, Any]:
    """移动或整理 samples 下的样本。"""
    return _safe_call(sample_crud.move_sample, path, destination_name, destination_subdir, overwrite)


@mcp.tool()
def quarantine_sample(path: str, overwrite: bool = False) -> dict[str, Any]:
    """把 samples 下样本移入 samples\\_quarantine。"""
    return _safe_call(sample_crud.quarantine_sample, path, overwrite)


@mcp.tool()
def delete_sample(path: str, dry_run: bool = True) -> dict[str, Any]:
    """删除 samples 下样本；默认 dry_run=True。"""
    return _safe_call(sample_crud.delete_sample, path, dry_run)


@mcp.tool()
def workspace_read_text(path: str, max_chars: int = 12000) -> dict[str, Any]:
    """读取 notes/reports/scripts/exports 下的文本文件内容，适合 AI 后续处理。"""
    return _safe_call(workspace_crud.workspace_read_text, path, max_chars)


@mcp.tool()
def workspace_write_text(
    path: str,
    content: str,
    mode: str = "replace",
    create_dirs: bool = True,
    overwrite: bool = True,
) -> dict[str, Any]:
    """在 notes/reports/scripts/exports 下创建或更新文本文件。"""
    return _safe_call(workspace_crud.workspace_write_text, path, content, mode, create_dirs, overwrite)


@mcp.tool()
def workspace_copy_artifact(path: str, destination_path: str, overwrite: bool = False) -> dict[str, Any]:
    """复制 notes/reports/scripts/exports/patches/projects 下的文件或目录。"""
    return _safe_call(workspace_crud.workspace_copy_artifact, path, destination_path, overwrite)


@mcp.tool()
def workspace_move_artifact(path: str, destination_path: str, overwrite: bool = False) -> dict[str, Any]:
    """移动或重命名 notes/reports/scripts/exports/patches/projects 下的文件或目录。"""
    return _safe_call(workspace_crud.workspace_move_artifact, path, destination_path, overwrite)


@mcp.tool()
def workspace_delete_artifact(path: str, dry_run: bool = True) -> dict[str, Any]:
    """删除 notes/reports/scripts/exports/patches/projects 下的文件或目录；默认 dry_run=True。"""
    return _safe_call(workspace_crud.workspace_delete_artifact, path, dry_run)


@mcp.tool()
def toolbox_list() -> dict[str, Any]:
    """列出 ReverseLab allowlist 工具箱：DiE、Rizin/Cutter、Ghidra、PE-bear、Procmon、x64dbg。"""
    return _safe_call(toolbox.toolbox_list)


@mcp.tool()
def toolbox_version(tool_id: str, timeout: int = 30) -> dict[str, Any]:
    """对 allowlist 中支持安全版本探测的 CLI 工具执行版本查询。"""
    return _safe_call(toolbox.toolbox_version, tool_id, timeout)


@mcp.tool()
def toolbox_launch(tool_id: str, target_path: str = "", extra_args: str = "", visible: bool = True) -> dict[str, Any]:
    """启动 allowlist 中的 GUI/交互工具，可选打开目标文件；不提供任意 shell。"""
    return _safe_call(toolbox.toolbox_launch, tool_id, target_path, extra_args, visible)


@mcp.tool()
def procmon_start_capture(pml_path: str = "", quiet: bool = True) -> dict[str, Any]:
    """启动 Procmon64 capture，backing file 默认写入 exports\\procmon。"""
    return _safe_call(toolbox.procmon_start_capture, pml_path, quiet)


@mcp.tool()
def procmon_stop_capture(timeout: int = 30) -> dict[str, Any]:
    """停止 Procmon capture。"""
    return _safe_call(toolbox.procmon_stop_capture, timeout)


@mcp.tool()
def procmon_export_csv(
    pml_path: str,
    output_path: str = "",
    load_config_path: str = "",
    apply_filter: bool = False,
    terminate_when_done: bool = True,
    wait_timeout: int = 60,
) -> dict[str, Any]:
    """将 exports\\procmon 下的 PML 导出为 CSV，可选加载 Procmon 配置并应用当前过滤器。"""
    return _safe_call(
        toolbox.procmon_export_csv,
        pml_path,
        output_path,
        load_config_path,
        apply_filter,
        terminate_when_done,
        wait_timeout,
    )


@mcp.tool()
def rizin_write_bytes(
    path: str,
    offset: int,
    new_bytes_hex: str,
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """使用 Rizin raw write 在 patches 副本上写入十六进制字节。"""
    return _safe_call(rizin_write.rizin_write_bytes, path, offset, new_bytes_hex, output_path, case_name, overwrite, timeout)


@mcp.tool()
def rizin_assemble_bytes(
    assembly: str,
    arch: str = "x86",
    bits: int = 64,
    cpu: str = "",
    syntax: str = "",
) -> dict[str, Any]:
    """调用 rz-asm 把汇编文本转成机器码。"""
    return _safe_call(rizin_write.rizin_assemble_bytes, assembly, arch, bits, cpu, syntax)


@mcp.tool()
def rizin_assemble_patch(
    path: str,
    offset: int,
    assembly: str,
    arch: str = "x86",
    bits: int = 64,
    cpu: str = "",
    syntax: str = "",
    output_path: str = "",
    case_name: str = "",
    overwrite: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """先用 rz-asm 汇编，再对 patches 副本做 patch。"""
    return _safe_call(
        rizin_write.rizin_assemble_patch,
        path,
        offset,
        assembly,
        arch,
        bits,
        cpu,
        syntax,
        output_path,
        case_name,
        overwrite,
        timeout,
    )


@mcp.tool()
def make_x64dbg_breakpoint_script(
    sample_path: str = "",
    summary_path: str = "",
    output_path: str = "",
    presets: str = "",
    api_names: str = "",
    function_query: str = "",
    function_addresses: str = "",
    function_limit: int = 10,
) -> dict[str, Any]:
    """根据 triage/Ghidra summary 生成 x64dbg 断点脚本，写入 scripts\\debug。"""
    return _safe_call(
        debug_scripts.make_x64dbg_breakpoint_script,
        sample_path,
        summary_path,
        output_path,
        presets,
        api_names,
        function_query,
        function_addresses,
        function_limit,
    )


@mcp.tool()
def make_pe_crypto_unpack_plan(
    sample_path: str,
    summary_path: str = "",
    mode: str = "both",
    output_path: str = "",
    include_frida: bool = True,
    focus_limit: int = 12,
) -> dict[str, Any]:
    """生成 PE 解密/去壳动态分析包：x64dbg 断点脚本、Windows Frida hook、重点函数队列和 JSON plan。"""
    return _safe_call(crypto_unpack.make_pe_crypto_unpack_plan, sample_path, summary_path, mode, output_path, include_frida, focus_limit)


@mcp.tool()
def carve_payloads_from_dump(
    source_path: str,
    output_subdir: str = "",
    import_to_samples: bool = True,
    max_candidates: int = 20,
    min_size: int = 256,
    run_triage: bool = True,
) -> dict[str, Any]:
    """从 dump/decrypted buffer 中自动 carve PE/DEX payload，并可导入 samples\\unpacked 供下一轮分析。"""
    return _safe_call(
        unpack_intake.carve_payloads_from_dump,
        source_path,
        output_subdir,
        import_to_samples,
        max_candidates,
        min_size,
        run_triage,
    )


@mcp.tool()
def parse_android_crypto_unpack_result(result_json_path: str, output_path: str = "") -> dict[str, Any]:
    """解析 android_crypto_unpack_recipe/Frida JSON，提取 key/iv、crypto op、动态 dex、native loader、mmap/mprotect、RegisterNatives 证据。"""
    return _safe_call(unpack_intake.parse_android_crypto_unpack_result, result_json_path, output_path)


@mcp.tool()
def extract_frida_buffers(
    result_json_path: str,
    output_subdir: str = "",
    carve: bool = True,
    import_to_samples: bool = True,
    max_buffers: int = 50,
) -> dict[str, Any]:
    """从 Frida JSON 的 data_hex 消息中落盘二进制 buffer，并可自动 carve PE/DEX payload。"""
    return _safe_call(unpack_intake.extract_frida_buffers, result_json_path, output_subdir, carve, import_to_samples, max_buffers)


@mcp.tool()
def make_crypto_replay_scaffold(
    result_json_path: str,
    output_path: str = "",
    algorithm_hint: str = "",
) -> dict[str, Any]:
    """从 Frida crypto 证据生成可运行的 Python 解密/Hash/HMAC 复现脚本骨架。"""
    return _safe_call(unpack_intake.make_crypto_replay_scaffold, result_json_path, output_path, algorithm_hint)


@mcp.tool()
def solve_crypto_from_evidence(
    result_json_path: str,
    output_subdir: str = "",
    algorithm_hint: str = "",
    carve_matches: bool = True,
) -> dict[str, Any]:
    """从 Frida key/IV/input/output evidence 自动尝试常见解密/hash/HMAC，落盘命中结果并可继续 carve PE/DEX。"""
    return _safe_call(unpack_intake.solve_crypto_from_evidence, result_json_path, output_subdir, algorithm_hint, carve_matches)


@mcp.tool()
def postprocess_frida_crypto_result(
    result_json_path: str,
    output_subdir: str = "",
    algorithm_hint: str = "",
    include_replay: bool = True,
    extract_buffers: bool = True,
    carve: bool = True,
) -> dict[str, Any]:
    """对 Frida crypto/unpack JSON 一键执行 parse、solve、replay scaffold、buffer extract/carve，并输出总 manifest。"""
    return _safe_call(
        unpack_intake.postprocess_frida_crypto_result,
        result_json_path,
        output_subdir,
        algorithm_hint,
        include_replay,
        extract_buffers,
        carve,
    )


@mcp.tool()
def make_procmon_filters(
    sample_path: str = "",
    summary_path: str = "",
    output_path: str = "",
    presets: str = "",
    extra_path_contains: str = "",
    include_noise_excludes: bool = True,
    max_path_hints: int = 8,
) -> dict[str, Any]:
    """根据样本导入表和 Ghidra summary 生成 Procmon 过滤计划，写入 scripts\\procmon。"""
    return _safe_call(
        procmon_filters.make_procmon_filters,
        sample_path,
        summary_path,
        output_path,
        presets,
        extra_path_contains,
        include_noise_excludes,
        max_path_hints,
    )


@mcp.tool()
def triage_to_notes(
    sample_path: str,
    summary_path: str = "",
    output_path: str = "",
    overwrite: bool = False,
    max_functions: int = 15,
    max_imports: int = 20,
    max_strings: int = 20,
) -> dict[str, Any]:
    """根据 triage 和可选的 Ghidra summary 生成分析笔记骨架，写入 notes\\*.md。"""
    return _safe_call(
        analysis_notes.triage_to_notes,
        sample_path,
        summary_path,
        output_path,
        overwrite,
        max_functions,
        max_imports,
        max_strings,
    )


@mcp.tool()
def extract_iocs_from_summary(
    summary_path: str = "",
    sample_path: str = "",
    note_path: str = "",
    output_path: str = "",
) -> dict[str, Any]:
    """从 Ghidra summary、triage 字符串和分析笔记中提取 IOC 与行为线索，写入 exports\\iocs。"""
    return _safe_call(
        ioc_extract.extract_iocs_from_summary,
        summary_path,
        sample_path,
        note_path,
        output_path,
    )


@mcp.tool()
def refine_ioc_sources(ioc_json_path: str, output_path: str = "") -> dict[str, Any]:
    """将 IOC 条目按 static_confirmed / mixed / note_only 分层，便于后续 YARA / Sigma 精修。"""
    return _safe_call(ioc_extract.refine_ioc_sources, ioc_json_path, output_path)


@mcp.tool()
def make_yara_stub(
    sample_path: str = "",
    summary_path: str = "",
    ioc_json_path: str = "",
    rule_name: str = "",
    output_path: str = "",
    max_strings: int = 10,
    max_imports: int = 6,
) -> dict[str, Any]:
    """根据样本、Ghidra summary 和 IOC 产物生成可继续精修的 YARA 草案，写入 exports\\yara。"""
    return _safe_call(
        yara_stub.make_yara_stub,
        sample_path,
        summary_path,
        ioc_json_path,
        rule_name,
        output_path,
        max_strings,
        max_imports,
    )


@mcp.tool()
def make_sigma_stub(
    sample_path: str = "",
    summary_path: str = "",
    ioc_json_path: str = "",
    rule_name: str = "",
    output_path: str = "",
) -> dict[str, Any]:
    """根据样本、IOC 结果和可选 summary 生成可继续精修的 Sigma 草案，写入 exports\\sigma。"""
    return _safe_call(
        sigma_stub.make_sigma_stub,
        sample_path,
        summary_path,
        ioc_json_path,
        rule_name,
        output_path,
    )


@mcp.tool()
def python_re_tool_status() -> dict[str, Any]:
    """检查 LIEF/Frida/angr/capstone/keystone 等 Python 逆向库是否已安装。"""
    return _safe_call(python_re_tools.python_re_tool_status)


@mcp.tool()
def python_re_tool_install(tool_id: str, version: str = "", user_scope: bool = True, timeout: int = 600) -> dict[str, Any]:
    """按 allowlist 安装 Python 逆向库，例如 lief、frida、angr。"""
    return _safe_call(python_re_tools.python_re_tool_install, tool_id, version, user_scope, timeout)


@mcp.tool()
def python_re_tool_version(tool_id: str) -> dict[str, Any]:
    """查询指定 Python 逆向库的版本和模块路径。"""
    return _safe_call(python_re_tools.python_re_tool_version, tool_id)


@mcp.tool()
def mcp_update_audit(include_global: bool = True, include_workspace: bool = True) -> dict[str, Any]:
    """审计工作区/全局 MCP 配置中的本地 Git、npm、PyPI/uvx 工具是否有上游更新或弃用风险。"""
    return _safe_call(mcp_update.mcp_update_audit, include_global, include_workspace)


@mcp.tool()
def sample_full_workup(
    sample_path: str,
    summary_path: str = "",
    run_ghidra: bool = False,
    generate_rules: bool = True,
    overwrite_note: bool = True,
    report_path: str = "",
    ghidra_timeout_seconds: int = 1800,
) -> dict[str, Any]:
    """一键自动逆向工作流：triage、可选 Ghidra、重点函数队列、x64dbg/Procmon 计划、IOC、YARA/Sigma 草案和总控 manifest。"""
    return _safe_call(
        workflow.sample_full_workup,
        sample_path,
        summary_path,
        run_ghidra,
        generate_rules,
        overwrite_note,
        report_path,
        ghidra_timeout_seconds,
    )


@mcp.tool()
def sample_autopilot_round(
    manifest_path: str = "",
    max_actions: int = 4,
    execute: bool = False,
) -> dict[str, Any]:
    """从 battleplan manifest 自动规划/执行下一轮逆向动作：补 Ghidra、生成函数断点、行为断点、unpacking 断点和 Procmon 视图。"""
    return _safe_call(workflow.sample_autopilot_round, manifest_path, max_actions, execute)


# ── Web CTF tools ──

@mcp.tool()
def http_probe(url: str, timeout: int = 15) -> dict[str, Any]:
    """对目标 URL 发起 GET 探测，收集 header/body/cookie/指纹。"""
    return _safe_call(web_ctf.http_probe, url, timeout)


@mcp.tool()
def kb_router(query: str) -> dict[str, Any]:
    """按攻击信号搜索知识库，返回匹配的技术文件和路径。"""
    return _safe_call(web_ctf.kb_router, query)


@mcp.tool()
def kb_read_file(technique_path: str) -> dict[str, Any]:
    """读取知识库技术文件内容。路径格式如 '02-auth/jwt/01-alg-none.md'。"""
    return _safe_call(web_ctf.kb_read_file, technique_path)


@mcp.tool()
def kb_catalog() -> dict[str, Any]:
    """列出知识库所有分类、条目数和文件数。"""
    return _safe_call(web_ctf.kb_catalog)


@mcp.tool()
def ctf_new_challenge(name: str, url: str = "") -> dict[str, Any]:
    """创建新的 CTF 题目 case 目录，从模板初始化。"""
    return _safe_call(web_ctf.ctf_new_challenge, name, url)


@mcp.tool()
def run_ctf_tool(tool: str, args: str, timeout: int = 120) -> dict[str, Any]:
    """运行 CTF 工具。tool: sqlmap/dirsearch/jwt_tool/tplmap。args: 命令行参数。"""
    return _safe_call(web_ctf.run_ctf_tool, tool, args, timeout)


@mcp.tool()
def ctf_tool_status() -> dict[str, Any]:
    """检查 CTF 工具安装状态。"""
    return _safe_call(web_ctf.ctf_tool_status)


# ── Skill / project setup ──

@mcp.tool()
def project_skills_status() -> dict[str, Any]:
    """查看项目级 skills/MCP 安装状态和推荐安装命令。"""
    skills_dir = REVERSE_ROOT / "tools" / "skills" / "mcp"
    status = {
        "ghidra_mcp": {
            "path": str((skills_dir / "GhidraMCP" / "bridge_mcp_ghidra.py").relative_to(REVERSE_ROOT)),
            "installed": (skills_dir / "GhidraMCP" / "bridge_mcp_ghidra.py").exists(),
            "install": "git clone https://github.com/LaurieWired/GhidraMCP.git tools/skills/mcp/GhidraMCP",
        },
        "jshook": {
            "path": str((skills_dir / "JSHookLocal" / "dist" / "index.js").relative_to(REVERSE_ROOT)),
            "installed": (skills_dir / "JSHookLocal" / "dist" / "index.js").exists(),
            "install": "git clone https://github.com/wuji1/jshook-reverse-tool.git tools/skills/mcp/JSHookLocal && cd tools/skills/mcp/JSHookLocal && npm install && npm run build",
        },
        "reverse_lab_tools": {
            "path": str((skills_dir / "ReverseLabToolsMCP" / "reverse_lab_tools_mcp.py").relative_to(REVERSE_ROOT)),
            "installed": (skills_dir / "ReverseLabToolsMCP" / "reverse_lab_tools_mcp.py").exists(),
            "install": "cd tools/skills/mcp/ReverseLabToolsMCP && uv sync",
        },
    }
    installed = sum(1 for s in status.values() if s["installed"])
    return {
        "skills": status,
        "installed": installed,
        "total": len(status),
        "project_root": str(REVERSE_ROOT),
        "next": (
            "All skills ready" if installed == len(status)
            else f"Run install commands above for missing skills ({len(status) - installed} remaining)"
        ),
    }


def _self_test(path: str) -> int:
    target = str(resolve_file(path))
    checks = {
        "hash_file": hash_file(target),
        "die_scan": die_scan(target),
        "rizin_bin_info": rizin_bin_info(target),
        "rizin_sections": rizin_sections(target),
        "rizin_imports": rizin_imports(target, limit=10),
        "rizin_strings": rizin_strings(target, limit=10),
        "triage_pe": triage_pe(target, write_markdown=True),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _headless_test(path: str) -> int:
    target = str(resolve_file(path))
    result = ghidra_headless_analyze(
        target,
        project_name="mcp_headless_smoke",
        overwrite=True,
        analysis_timeout_seconds=600,
        process_timeout_seconds=1800,
        function_limit=30,
        string_limit=30,
        import_limit=30,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("returncode") == 0 and result.get("summary") else 1


def _summary_test(summary_path: str = "") -> int:
    checks = {
        "ghidra_summary_list": ghidra_summary_list(),
        "ghidra_summary_overview": ghidra_summary_overview(summary_path),
        "ghidra_summary_functions": ghidra_summary_functions(summary_path, query="entry", limit=5),
        "ghidra_summary_imports": ghidra_summary_imports(summary_path, query="Create", limit=5),
        "ghidra_summary_strings": ghidra_summary_strings(summary_path, query="dll", limit=5),
        "ghidra_summary_call_focus": ghidra_summary_call_focus(summary_path, query="Create\nhttp", behavior="network", limit=5),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _mutation_test(path: str) -> int:
    target = str(resolve_file(path))
    copied = copy_sample_to_patches(target, case_name="mcp_mutation_smoke", output_name="notepad_copy.exe", overwrite=True)
    patched = patch_bytes(target, offset=0, new_bytes_hex="5A", case_name="mcp_mutation_smoke", overwrite=True)
    delete_copy = copy_sample_to_patches(target, case_name="mcp_mutation_delete_smoke", output_name="delete_me.exe", overwrite=True)
    dry_delete = delete_generated_artifact(delete_copy.get("destination_path", ""), dry_run=True)
    real_delete = delete_generated_artifact(delete_copy.get("destination_path", ""), dry_run=False)
    checks = {
        "copy_sample_to_patches": copied,
        "patch_bytes": patched,
        "delete_generated_artifact_dry_run": dry_delete,
        "delete_generated_artifact": real_delete,
        "list_generated_artifacts": list_generated_artifacts("patches", limit=10),
        "mutation_audit_tail": mutation_audit_tail(limit=10),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _pe_patch_test(path: str) -> int:
    target = str(resolve_file(path))
    rva_mapping = pe_address_to_offset(target, "0x0", address_type="rva")
    image_base = rva_mapping.get("image_base", 0)
    va_mapping = pe_address_to_offset(target, f"0x{image_base:X}", address_type="va")
    patched = patch_pe_bytes(
        target,
        address="0x0",
        new_bytes_hex="5A",
        address_type="rva",
        case_name="mcp_pe_patch_smoke",
        overwrite=True,
    )
    checks = {
        "pe_address_to_offset_rva0": rva_mapping,
        "pe_address_to_offset_image_base": va_mapping,
        "patch_pe_bytes": patched,
        "mutation_audit_tail": mutation_audit_tail(limit=10),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _pattern_test(path: str) -> int:
    target = str(resolve_file(path))
    search = search_pattern(target, "4D 5A ?? 00 03 00 00 00", max_matches=3)
    patched = patch_pattern(
        target,
        pattern="4D 5A ?? 00 03 00 00 00",
        new_bytes_hex="5A 5A 90 00 03 00 00 00",
        occurrence=0,
        require_unique=True,
        case_name="mcp_pattern_patch_smoke",
        overwrite=True,
    )
    report = generate_patch_report(source_contains="notepad.exe", limit=20)
    checks = {
        "search_pattern": search,
        "patch_pattern": patched,
        "generate_patch_report": report,
        "mutation_audit_tail": mutation_audit_tail(limit=10),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _toolbox_test() -> int:
    listed = toolbox_list()
    checks = {
        "toolbox_list": listed,
        "toolbox_version_rz_bin": toolbox_version("rz_bin"),
        "toolbox_version_rz_hash": toolbox_version("rz_hash"),
        "toolbox_version_die_cli": toolbox_version("die_cli"),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _debug_script_test(path: str, summary_path: str = "") -> int:
    target = str(resolve_file(path))
    result = make_x64dbg_breakpoint_script(
        sample_path=target,
        summary_path=summary_path,
        presets="loader,file,registry,network,crypto,antidebug",
        function_query="FUN_140001",
        function_limit=3,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("output_path") else 1


def _procmon_filter_test(path: str, summary_path: str = "") -> int:
    target = str(resolve_file(path))
    result = make_procmon_filters(
        sample_path=target,
        summary_path=summary_path,
        presets="file,registry,process,network,image",
        include_noise_excludes=True,
        max_path_hints=6,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("output_path") and result.get("csv_path") else 1


def _triage_note_test(path: str, summary_path: str = "") -> int:
    target = str(resolve_file(path))
    output = str((analysis_notes.NOTES_DIR / "notepad_generated_analysis.md").resolve()) if hasattr(analysis_notes, "NOTES_DIR") else ""
    result = triage_to_notes(
        sample_path=target,
        summary_path=summary_path,
        output_path=output,
        overwrite=True,
        max_functions=8,
        max_imports=12,
        max_strings=12,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("output_path") else 1


def _ioc_extract_test(path: str, summary_path: str = "", note_path: str = "") -> int:
    target = str(resolve_file(path))
    result = extract_iocs_from_summary(summary_path, target, note_path, "")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("json_path") and result.get("markdown_path") else 1


def _yara_stub_test(path: str, summary_path: str = "", ioc_json_path: str = "") -> int:
    target = str(resolve_file(path))
    result = make_yara_stub(
        sample_path=target,
        summary_path=summary_path,
        ioc_json_path=ioc_json_path,
        rule_name="notepad_auto",
        max_strings=8,
        max_imports=4,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("rule_path") and result.get("manifest_path") else 1


def _pe_crypto_unpack_test(path: str, summary_path: str = "") -> int:
    target = str(resolve_file(path))
    result = make_pe_crypto_unpack_plan(
        sample_path=target,
        summary_path=summary_path,
        mode="both",
        include_frida=True,
        focus_limit=8,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("plan_path") and result.get("x64dbg_script_path") else 1


def _carve_payloads_test(path: str) -> int:
    target = str(resolve_file(path))
    result = carve_payloads_from_dump(target, "cli", True, 5, 128, False)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("manifest_path") else 1


def _android_crypto_parse_test(path: str) -> int:
    result = parse_android_crypto_unpack_result(path, "")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("output_path") else 1


def _frida_buffer_extract_test(path: str) -> int:
    result = extract_frida_buffers(path, "cli", True, True, 10)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("manifest_path") else 1


def _crypto_replay_scaffold_test(path: str) -> int:
    result = make_crypto_replay_scaffold(path, "", "")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("script_path") else 1


def _crypto_solve_test(path: str) -> int:
    result = solve_crypto_from_evidence(path, "cli", "", True)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("manifest_path") else 1


def _frida_crypto_postprocess_test(path: str) -> int:
    result = postprocess_frida_crypto_result(path, "cli", "", True, True, True)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("manifest_path") else 1


def _sigma_stub_test(path: str, summary_path: str = "", ioc_json_path: str = "") -> int:
    target = str(resolve_file(path))
    result = make_sigma_stub(
        sample_path=target,
        summary_path=summary_path,
        ioc_json_path=ioc_json_path,
        rule_name="notepad_auto",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("yaml_path") and result.get("manifest_path") else 1


def _procmon_export_test(pml_path: str, config_path: str = "") -> int:
    result = procmon_export_csv(
        pml_path=pml_path,
        output_path="",
        load_config_path=config_path,
        apply_filter=False,
        terminate_when_done=True,
        wait_timeout=20,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("output_path") else 1


def _ioc_refine_test(ioc_json_path: str) -> int:
    result = refine_ioc_sources(ioc_json_path=ioc_json_path, output_path="")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("json_path") and result.get("markdown_path") else 1


def _workspace_crud_test() -> int:
    test_dir = REVERSE_ROOT
    base = str(test_dir / "notes" / "mcp_workspace_crud_test.md")
    copy_path = str(test_dir / "reports" / "mcp_workspace_crud_test_copy.md")
    moved_path = str(test_dir / "reports" / "mcp_workspace_crud_test_moved.md")
    checks = {
        "workspace_write_text_create": workspace_write_text(base, "# CRUD Test\n", mode="replace", create_dirs=True, overwrite=True),
        "workspace_write_text_append": workspace_write_text(base, "append line\n", mode="append", create_dirs=True, overwrite=True),
        "workspace_read_text": workspace_read_text(base, max_chars=2000),
        "workspace_copy_artifact": workspace_copy_artifact(base, copy_path, overwrite=True),
        "workspace_move_artifact": workspace_move_artifact(copy_path, moved_path, overwrite=True),
        "workspace_delete_artifact_dry_run": workspace_delete_artifact(moved_path, dry_run=True),
        "workspace_delete_artifact": workspace_delete_artifact(moved_path, dry_run=False),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _sample_crud_test(path: str) -> int:
    imported = import_sample(path, destination_name="notepad_sample.exe", destination_subdir="smoke", overwrite=True, move_source=False)
    sample_path = imported.get("destination_path", "")
    checks = {
        "import_sample": imported,
        "list_samples": list_samples(limit=20, subdir="smoke"),
        "copy_sample": copy_sample(sample_path, destination_name="notepad_copy.exe", destination_subdir="smoke\\copies", overwrite=True),
        "rename_sample": rename_sample(sample_path, new_name="notepad_renamed.exe", overwrite=True),
    }
    renamed_path = checks["rename_sample"].get("destination_path", "")
    checks["move_sample"] = move_sample(renamed_path, destination_name="notepad_moved.exe", destination_subdir="smoke\\moved", overwrite=True)
    moved_path = checks["move_sample"].get("destination_path", "")
    checks["quarantine_sample"] = quarantine_sample(moved_path, overwrite=True)
    quarantined_path = checks["quarantine_sample"].get("destination_path", "")
    checks["delete_sample_dry_run"] = delete_sample(quarantined_path, dry_run=True)
    checks["delete_sample"] = delete_sample(quarantined_path, dry_run=False)
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _rizin_write_test(path: str) -> int:
    target = str(resolve_file(path))
    checks = {
        "rizin_assemble_bytes": rizin_assemble_bytes("nop; ret", arch="x86", bits=64),
        "rizin_write_bytes": rizin_write_bytes(target, offset=0, new_bytes_hex="5A 5A", case_name="mcp_rizin_write_smoke", overwrite=True),
        "rizin_assemble_patch": rizin_assemble_patch(target, offset=0, assembly="nop", arch="x86", bits=64, case_name="mcp_rizin_asm_smoke", overwrite=True),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _python_re_tools_test() -> int:
    checks = {
        "python_re_tool_status": python_re_tool_status(),
        "python_re_tool_version_lief": python_re_tool_version("lief"),
        "python_re_tool_version_frida": python_re_tool_version("frida"),
        "python_re_tool_version_angr": python_re_tool_version("angr"),
        "python_re_tool_version_capstone": python_re_tool_version("capstone"),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def _mcp_update_audit_test() -> int:
    checks = {
        "mcp_update_audit": mcp_update_audit(True, True),
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if "error" not in checks["mcp_update_audit"] else 1


def _sample_full_workup_test(path: str, summary_path: str = "", run_ghidra: bool = False) -> int:
    result = sample_full_workup(path, summary_path, run_ghidra, True, True, "", 1800)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result and result.get("error_count", 0) == 0 else 1


def _sample_autopilot_round_test(manifest_path: str = "", execute: bool = False) -> int:
    result = sample_autopilot_round(manifest_path, 4, execute)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result else 1


def _android_mumu_test() -> int:
    checks = {
        "android_mumu_instance_info": android_mumu_instance_info(""),
        "android_adb_connect": android_adb_connect(""),
        "android_adb_devices": android_adb_devices(),
        "android_device_info": android_device_info(""),
        "android_list_packages_nemu": android_list_packages("", "nemu", 20),
        "android_current_activity": android_current_activity(""),
        "android_package_paths_systemui": android_package_paths("com.android.systemui", ""),
        "android_capture_screenshot": android_capture_screenshot(
            "",
            str(android_mumu._app_output_path("com.android.systemui", "screenshots", "mumu-screenshot", ".png")),
        ),
        "android_package_info_systemui": android_package_info(
            "com.android.systemui",
            "",
            str(android_mumu._app_output_path("com.android.systemui", "package-info", "package-info-com.android.systemui", ".txt")),
        ),
        "android_frida_status": android_frida_status(""),
        "android_frida_template_library": android_frida_template_library(),
        "android_frida_render_template": android_frida_render_template(
            "native_export_log",
            '{"library_name":"libandroid_runtime.so","export_name":"_ZN7android14AndroidRuntime5startEPKcS1_b"}',
        ),
        "android_app_baseline_systemui": android_app_baseline(
            package_name="com.android.systemui",
            apk_path="",
            serial="",
            reinstall=False,
            grant_permissions=False,
            launch=False,
            clear_logcat_first=False,
            logcat_lines=120,
            output_path="",
        ),
        "android_pull_artifact_recipe_systemui": android_pull_artifact_recipe(
            "com.android.systemui",
            "",
            False,
            True,
            True,
            True,
            120,
            "",
        ),
        "android_package_fs_recipe_systemui": android_package_fs_recipe(
            "com.android.systemui",
            "",
            True,
            "shared_prefs,files",
            2,
            80,
            "",
        ),
        "android_runtime_file_watch_recipe_lawnchair": android_runtime_file_watch_recipe(
            "app.lawnchair",
            "",
            True,
            2,
            "shared_prefs,files",
            2,
            80,
            "",
        ),
        "android_http_observation_recipe_systemui": android_http_observation_recipe(
            "com.android.systemui",
            "",
            "",
            False,
            2,
            False,
            120,
            "okhttp_newcall,okhttp_response",
            "",
        ),
        "android_crypto_unpack_templates": {
            template_id: android_frida_render_template(template_id, "")
            for template_id in android_mumu.ANDROID_CRYPTO_UNPACK_TEMPLATES.split(",")
        },
        "android_logcat_dump": android_logcat_dump(
            "",
            str(android_mumu._app_output_path("com.android.systemui", "logs", "mumu-logcat", ".txt")),
            clear_before=False,
            max_lines=200,
        ),
    }
    frida_status_result = checks["android_frida_status"]
    if (
        "error" not in frida_status_result
        and frida_status_result.get("matched_device")
        and frida_status_result.get("frida_server_running")
    ):
        checks["android_frida_processes_systemui"] = android_frida_processes("", "systemui", 20)
        checks["android_frida_run_script_systemui"] = android_frida_run_script(
            "com.android.systemui",
            "send({event: 'hello', pid: Process.id});",
            "",
            "attach",
            2,
            str(android_mumu._app_output_path("com.android.systemui", "frida", "frida-run-com.android.systemui", ".json")),
        )
    else:
        checks["android_frida_processes_systemui"] = {"skipped": True, "reason": "Frida bridge or frida-server unavailable"}
        checks["android_frida_run_script_systemui"] = {"skipped": True, "reason": "Frida bridge or frida-server unavailable"}
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all("error" not in value for value in checks.values()) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="ReverseLab local tools MCP server")
    parser.add_argument("--self-test", metavar="FILE", help="run tool self-test against a file and exit")
    parser.add_argument("--headless-test", metavar="FILE", help="run Ghidra headless smoke test against a file and exit")
    parser.add_argument("--summary-test", nargs="?", const="", metavar="SUMMARY_JSON", help="run Ghidra summary query smoke test and exit")
    parser.add_argument("--mutation-test", metavar="FILE", help="run safe mutation smoke test against a file and exit")
    parser.add_argument("--pe-patch-test", metavar="FILE", help="run PE RVA/VA patch smoke test against a file and exit")
    parser.add_argument("--pattern-test", metavar="FILE", help="run pattern patch/report smoke test against a file and exit")
    parser.add_argument("--toolbox-test", action="store_true", help="run toolbox list/version smoke test and exit")
    parser.add_argument("--debug-script-test", metavar="FILE", help="run x64dbg script generation smoke test against a file and exit")
    parser.add_argument("--debug-script-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --debug-script-test")
    parser.add_argument("--procmon-filter-test", metavar="FILE", help="run Procmon filter generation smoke test against a file and exit")
    parser.add_argument("--procmon-filter-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --procmon-filter-test")
    parser.add_argument("--triage-note-test", metavar="FILE", help="run triage-to-notes generation smoke test against a file and exit")
    parser.add_argument("--triage-note-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --triage-note-test")
    parser.add_argument("--ioc-extract-test", metavar="FILE", help="run IOC extraction smoke test against a file and exit")
    parser.add_argument("--ioc-extract-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --ioc-extract-test")
    parser.add_argument("--ioc-extract-note", metavar="NOTE_MD", default="", help="optional note for --ioc-extract-test")
    parser.add_argument("--yara-stub-test", metavar="FILE", help="run YARA stub generation smoke test against a file and exit")
    parser.add_argument("--yara-stub-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --yara-stub-test")
    parser.add_argument("--yara-stub-ioc", metavar="IOC_JSON", default="", help="optional IOC JSON for --yara-stub-test")
    parser.add_argument("--pe-crypto-unpack-test", metavar="FILE", help="run PE crypto/unpack plan generation against a file and exit")
    parser.add_argument("--pe-crypto-unpack-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --pe-crypto-unpack-test")
    parser.add_argument("--carve-payloads-test", metavar="FILE", help="run PE/DEX dump carving against a file and exit")
    parser.add_argument("--android-crypto-parse-test", metavar="JSON", help="parse Android crypto/unpack Frida JSON and exit")
    parser.add_argument("--frida-buffer-extract-test", metavar="JSON", help="extract binary data_hex buffers from Frida JSON and exit")
    parser.add_argument("--crypto-replay-scaffold-test", metavar="JSON", help="generate crypto replay scaffold from Frida JSON and exit")
    parser.add_argument("--crypto-solve-test", metavar="JSON", help="solve crypto transforms from Frida key/IV/input/output evidence and exit")
    parser.add_argument("--frida-crypto-postprocess-test", metavar="JSON", help="run full Frida crypto parse/solve/replay/extract pipeline and exit")
    parser.add_argument("--sigma-stub-test", metavar="FILE", help="run Sigma stub generation smoke test against a file and exit")
    parser.add_argument("--sigma-stub-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --sigma-stub-test")
    parser.add_argument("--sigma-stub-ioc", metavar="IOC_JSON", default="", help="optional IOC JSON for --sigma-stub-test")
    parser.add_argument("--procmon-export-test", metavar="PML", help="run Procmon CSV export smoke test against a PML file and exit")
    parser.add_argument("--procmon-export-config", metavar="PMC", default="", help="optional Procmon config for --procmon-export-test")
    parser.add_argument("--ioc-refine-test", metavar="IOC_JSON", help="run IOC source refinement smoke test against an IOC JSON and exit")
    parser.add_argument("--workspace-crud-test", action="store_true", help="run workspace CRUD smoke test and exit")
    parser.add_argument("--sample-crud-test", metavar="FILE", help="run sample CRUD smoke test against a file and exit")
    parser.add_argument("--rizin-write-test", metavar="FILE", help="run Rizin write/assemble patch smoke test against a file and exit")
    parser.add_argument("--python-re-tools-test", action="store_true", help="run Python reverse-engineering library status/version test and exit")
    parser.add_argument("--mcp-update-audit-test", action="store_true", help="run MCP update/deprecation audit and exit")
    parser.add_argument("--sample-full-workup-test", metavar="FILE", help="run automated sample full workup against a file and exit")
    parser.add_argument("--sample-full-workup-summary", metavar="SUMMARY_JSON", default="", help="optional summary for --sample-full-workup-test")
    parser.add_argument("--sample-full-workup-ghidra", action="store_true", help="run Ghidra headless during --sample-full-workup-test")
    parser.add_argument("--sample-autopilot-round-test", nargs="?", const="", metavar="MANIFEST_JSON", help="plan next automated reverse-engineering round from a battleplan manifest and exit")
    parser.add_argument("--sample-autopilot-execute", action="store_true", help="execute planned actions for --sample-autopilot-round-test")
    parser.add_argument("--android-mumu-test", action="store_true", help="run MuMu ADB/Frida smoke test and exit")
    args = parser.parse_args()

    if args.self_test:
        raise SystemExit(_self_test(args.self_test))
    if args.headless_test:
        raise SystemExit(_headless_test(args.headless_test))
    if args.summary_test is not None:
        raise SystemExit(_summary_test(args.summary_test))
    if args.mutation_test:
        raise SystemExit(_mutation_test(args.mutation_test))
    if args.pe_patch_test:
        raise SystemExit(_pe_patch_test(args.pe_patch_test))
    if args.pattern_test:
        raise SystemExit(_pattern_test(args.pattern_test))
    if args.toolbox_test:
        raise SystemExit(_toolbox_test())
    if args.debug_script_test:
        raise SystemExit(_debug_script_test(args.debug_script_test, args.debug_script_summary))
    if args.procmon_filter_test:
        raise SystemExit(_procmon_filter_test(args.procmon_filter_test, args.procmon_filter_summary))
    if args.triage_note_test:
        raise SystemExit(_triage_note_test(args.triage_note_test, args.triage_note_summary))
    if args.ioc_extract_test:
        raise SystemExit(_ioc_extract_test(args.ioc_extract_test, args.ioc_extract_summary, args.ioc_extract_note))
    if args.yara_stub_test:
        raise SystemExit(_yara_stub_test(args.yara_stub_test, args.yara_stub_summary, args.yara_stub_ioc))
    if args.pe_crypto_unpack_test:
        raise SystemExit(_pe_crypto_unpack_test(args.pe_crypto_unpack_test, args.pe_crypto_unpack_summary))
    if args.carve_payloads_test:
        raise SystemExit(_carve_payloads_test(args.carve_payloads_test))
    if args.android_crypto_parse_test:
        raise SystemExit(_android_crypto_parse_test(args.android_crypto_parse_test))
    if args.frida_buffer_extract_test:
        raise SystemExit(_frida_buffer_extract_test(args.frida_buffer_extract_test))
    if args.crypto_replay_scaffold_test:
        raise SystemExit(_crypto_replay_scaffold_test(args.crypto_replay_scaffold_test))
    if args.crypto_solve_test:
        raise SystemExit(_crypto_solve_test(args.crypto_solve_test))
    if args.frida_crypto_postprocess_test:
        raise SystemExit(_frida_crypto_postprocess_test(args.frida_crypto_postprocess_test))
    if args.sigma_stub_test:
        raise SystemExit(_sigma_stub_test(args.sigma_stub_test, args.sigma_stub_summary, args.sigma_stub_ioc))
    if args.procmon_export_test:
        raise SystemExit(_procmon_export_test(args.procmon_export_test, args.procmon_export_config))
    if args.ioc_refine_test:
        raise SystemExit(_ioc_refine_test(args.ioc_refine_test))
    if args.workspace_crud_test:
        raise SystemExit(_workspace_crud_test())
    if args.sample_crud_test:
        raise SystemExit(_sample_crud_test(args.sample_crud_test))
    if args.rizin_write_test:
        raise SystemExit(_rizin_write_test(args.rizin_write_test))
    if args.python_re_tools_test:
        raise SystemExit(_python_re_tools_test())
    if args.mcp_update_audit_test:
        raise SystemExit(_mcp_update_audit_test())
    if args.sample_full_workup_test:
        raise SystemExit(_sample_full_workup_test(args.sample_full_workup_test, args.sample_full_workup_summary, args.sample_full_workup_ghidra))
    if args.sample_autopilot_round_test is not None:
        raise SystemExit(_sample_autopilot_round_test(args.sample_autopilot_round_test, args.sample_autopilot_execute))
    if args.android_mumu_test:
        raise SystemExit(_android_mumu_test())

    mcp.run()


if __name__ == "__main__":
    main()
