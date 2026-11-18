"""IDAPython batch exporter for the existing ReverseLab summary contract.

Invoked by IDA with -A -S; this imports the input into a fresh database and
does not start a debugger or execute the analyzed program.
"""
import json
import os
import traceback
from pathlib import Path


def export(options):
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_lines
    import ida_loader
    import ida_nalt
    import ida_segment
    import idautils
    import idc

    if not ida_auto.auto_wait():
        raise RuntimeError("IDA auto-analysis was cancelled")
    hx = None
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            hx = ida_hexrays
    except (ImportError, RuntimeError):
        pass

    def addr(ea):
        return hex(int(ea))

    def function_ref(ea):
        fn = ida_funcs.get_func(ea)
        return {"name": ida_funcs.get_func_name(fn.start_ea), "entry": addr(fn.start_ea)} if fn else None

    def xrefs(ea):
        result, count = [], 0
        for x in idautils.XrefsTo(ea, 0):
            count += 1
            if len(result) < 32:
                fn = function_ref(x.frm) or {}
                result.append({"from": addr(x.frm), "type": str(x.type),
                               "function": fn.get("name", ""), "function_entry": fn.get("entry", "")})
        return result, count

    imports = {}
    for module in range(ida_nalt.get_import_module_qty()):
        namespace = ida_nalt.get_import_module_name(module) or ""

        def capture(ea, name, ordinal, namespace=namespace):
            refs, total = xrefs(ea)
            imports[int(ea)] = {"name": name or f"ordinal_{ordinal}", "address": addr(ea),
                                "namespace": namespace, "reference_count": total, "xrefs": refs}
            return True

        ida_nalt.enum_import_names(module, capture)
    strings = {}
    items = idautils.Strings()
    items.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])
    for item in items:
        refs, total = xrefs(item.ea)
        strings[int(item.ea)] = {"address": addr(item.ea), "length": int(item.length),
                               "value": str(item), "reference_count": total, "xrefs": refs}
    starts = list(idautils.Functions())
    functions = []
    for ea in starts[:options["function_limit"]]:
        fn = ida_funcs.get_func(ea)
        callers, callees, import_refs, string_refs = {}, {}, {}, {}
        for x in idautils.XrefsTo(ea, 0):
            caller = function_ref(x.frm) if x.iscode else None
            if caller and len(callers) < 32:
                callers[caller["entry"]] = caller
        for insn in idautils.FuncItems(ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(insn)):
                continue
            for x in idautils.XrefsFrom(insn, 0):
                dest = int(x.to)
                if dest in imports and len(import_refs) < 64:
                    import_refs[dest] = {k: v for k, v in imports[dest].items() if k != "xrefs"}
                    import_refs[dest].update({"from": addr(insn), "type": str(x.type)})
                if dest in strings and len(string_refs) < 64:
                    string_refs[dest] = {k: v for k, v in strings[dest].items() if k != "xrefs"}
                    string_refs[dest].update({"from": addr(insn), "type": str(x.type)})
                other = ida_funcs.get_func(dest) if x.iscode else None
                if other and other.start_ea == dest and other.start_ea != ea and len(callees) < 32:
                    callees[dest] = function_ref(dest)
        decompile = {"status": "unavailable", "preview": "", "error": "Hex-Rays decompiler is unavailable for this processor"}
        if hx:
            try:
                cfunc = hx.decompile(ea)
                if cfunc is None:
                    raise RuntimeError("Hex-Rays returned no pseudocode")
                code = ida_lines.tag_remove(str(cfunc))
                decompile = {"status": "ok", "preview": code[:5000], "truncated": len(code) > 5000}
            except Exception as exc:
                decompile = {"status": "error", "preview": "", "error": str(exc)}
        segment = ida_segment.getseg(ea)
        functions.append({"name": ida_funcs.get_func_name(ea), "entry": addr(ea),
                          "body_size": sum(end - start for start, end in idautils.Chunks(ea)),
                          "parameter_count": None, "calling_convention": "", "signature": idc.get_type(ea) or "",
                          "thunk": bool(fn.flags & ida_funcs.FUNC_THUNK),
                          "external": bool(segment and segment.type == ida_segment.SEG_XTRN),
                          "callers": list(callers.values()), "callees": list(callees.values()),
                          "import_refs": list(import_refs.values()), "string_refs": list(string_refs.values()),
                          "decompile": decompile})
    blocks = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        blocks.append({"name": ida_segment.get_segm_name(seg), "start": addr(seg.start_ea),
                       "end": addr(seg.end_ea - 1), "size": int(seg.end_ea - seg.start_ea),
                       "read": bool(seg.perm & ida_segment.SEGPERM_READ),
                       "write": bool(seg.perm & ida_segment.SEGPERM_WRITE),
                       "execute": bool(seg.perm & ida_segment.SEGPERM_EXEC),
                       "initialized": bool(ida_bytes.is_loaded(seg.start_ea))})
    result = {"export_schema": "reverselab-ida-summary-v1", "backend": "ida", "run_id": options["run_id"],
              "analysis_complete": True, "ida_version": ida_kernwin.get_kernel_version(),
              "hexrays_available": hx is not None,
              "program": {"name": Path(options["target"]).name, "executable_path": options["target"],
                          "sha256": options["sha256"], "format": ida_loader.get_file_type_name(),
                          "language": ida_ida.inf_get_procname(), "bits": 64 if ida_ida.inf_is_64bit() else 32 if ida_ida.inf_is_32bit_exactly() else 16,
                          "compiler_spec": "", "image_base": addr(ida_nalt.get_imagebase()),
                          "min_address": addr(ida_ida.inf_get_min_ea()), "max_address": addr(ida_ida.inf_get_max_ea() - 1)},
              "memory_blocks": blocks, "functions_total": len(starts), "functions": functions,
              "functions_returned": len(functions), "imports_total": len(imports),
              "imports": list(imports.values())[:options["import_limit"]], "strings_total": len(strings),
              "strings": list(strings.values())[:options["string_limit"]]}
    result["imports_returned"] = len(result["imports"])
    result["strings_returned"] = len(result["strings"])
    return result


def main():
    import ida_pro
    import idc
    output = None
    try:
        options = json.loads(Path(idc.ARGV[1]).read_text(encoding="utf-8"))
        output = Path(options["output"])
        result = export(options)
        temporary = output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, output)
        print("ReverseLab IDA summary written: " + str(output))
        ida_pro.qexit(0)
    except Exception as exc:
        traceback.print_exc()
        if output:
            # Failed exports must not appear in the successful summary glob.
            output.with_suffix(".error.json").write_text(json.dumps({"error": str(exc)}, ensure_ascii=False), encoding="utf-8")
        ida_pro.qexit(1)


if __name__ == "__main__":
    main()
