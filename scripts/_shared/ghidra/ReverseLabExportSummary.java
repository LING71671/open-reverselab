// Export a compact JSON summary after Ghidra headless analysis.
//@category ReverseLab

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.DefinedStringIterator;

public class ReverseLabExportSummary extends GhidraScript {

	private static final int MAX_FUNCTION_EDGES = 32;
	private static final int MAX_FUNCTION_IMPORT_REFS = 64;
	private static final int MAX_FUNCTION_STRING_REFS = 64;
	private static final int MAX_DECOMPILE_CHARS = 5000;

	private int parseLimit(String[] args, int index, int defaultValue) {
		if (args.length <= index) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(args[index]);
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	private String addr(Address address) {
		return address == null ? "" : address.toString();
	}

	private String trunc(String value, int limit) {
		if (value == null) {
			return "";
		}
		if (value.length() <= limit) {
			return value;
		}
		return value.substring(0, limit) + "...";
	}

	private Map<String, Object> functionRef(Function f) {
		Map<String, Object> item = new LinkedHashMap<>();
		if (f == null) {
			item.put("name", "");
			item.put("entry", "");
			return item;
		}
		item.put("name", f.getName());
		item.put("entry", addr(f.getEntryPoint()));
		return item;
	}

	private String symbolKey(Symbol symbol) {
		return addr(symbol.getAddress());
	}

	private Map<String, Object> importRef(Symbol symbol) {
		Map<String, Object> item = new LinkedHashMap<>();
		item.put("name", symbol.getName());
		item.put("address", addr(symbol.getAddress()));
		item.put("namespace", symbol.getParentNamespace().getName(true));
		return item;
	}

	private Map<String, Object> stringRef(Data data, String value) {
		Map<String, Object> item = new LinkedHashMap<>();
		item.put("address", addr(data.getAddress()));
		item.put("length", data.getLength());
		item.put("value", value);
		return item;
	}

	private void addUniqueMap(List<Map<String, Object>> items, Set<String> seen, String key, Map<String, Object> value, int limit) {
		if (items.size() >= limit || seen.contains(key)) {
			return;
		}
		seen.add(key);
		items.add(value);
	}

	private List<Map<String, Object>> callersFor(Function f, ReferenceManager refs, int limit) {
		List<Map<String, Object>> callers = new ArrayList<>();
		Set<String> seen = new LinkedHashSet<>();
		ReferenceIterator iter = refs.getReferencesTo(f.getEntryPoint());
		while (iter.hasNext() && callers.size() < limit && !monitor.isCancelled()) {
			Reference ref = iter.next();
			Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
			if (caller == null || caller.isExternal()) {
				continue;
			}
			String key = addr(caller.getEntryPoint());
			Map<String, Object> item = functionRef(caller);
			item.put("from", addr(ref.getFromAddress()));
			item.put("type", ref.getReferenceType().toString());
			addUniqueMap(callers, seen, key, item, limit);
		}
		return callers;
	}

	private List<Map<String, Object>> calleesFor(Function f, ReferenceManager refs, Listing listing, int limit) {
		List<Map<String, Object>> callees = new ArrayList<>();
		Set<String> seen = new LinkedHashSet<>();
		InstructionIterator instructions = listing.getInstructions(f.getBody(), true);
		while (instructions.hasNext() && callees.size() < limit && !monitor.isCancelled()) {
			Instruction instruction = instructions.next();
			for (Reference ref : refs.getReferencesFrom(instruction.getAddress())) {
				if (!ref.getReferenceType().isCall()) {
					continue;
				}
				Function callee = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
				if (callee == null) {
					callee = currentProgram.getFunctionManager().getFunctionContaining(ref.getToAddress());
				}
				if (callee == null || callee.isExternal()) {
					continue;
				}
				String key = addr(callee.getEntryPoint());
				Map<String, Object> item = functionRef(callee);
				item.put("from", addr(ref.getFromAddress()));
				item.put("type", ref.getReferenceType().toString());
				addUniqueMap(callees, seen, key, item, limit);
			}
		}
		return callees;
	}

	private Map<String, Object> decompilePreview(Function f, DecompInterface decompiler) {
		Map<String, Object> out = new LinkedHashMap<>();
		if (f.isExternal() || f.isThunk()) {
			out.put("status", "skipped");
			out.put("reason", "external_or_thunk");
			return out;
		}
		try {
			DecompileResults result = decompiler.decompileFunction(f, 12, monitor);
			out.put("completed", result.decompileCompleted());
			out.put("status", result.decompileCompleted() ? "ok" : "error");
			out.put("error", result.getErrorMessage());
			if (result.getDecompiledFunction() != null) {
				String c = result.getDecompiledFunction().getC();
				out.put("chars_total", c == null ? 0 : c.length());
				out.put("preview", trunc(c, MAX_DECOMPILE_CHARS));
			}
		}
		catch (Exception e) {
			out.put("status", "error");
			out.put("error", e.toString());
		}
		return out;
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: ReverseLabExportSummary.java <output.json> [functionLimit] [stringLimit] [importLimit]");
		}

		File outputFile = new File(args[0]);
		File parent = outputFile.getParentFile();
		if (parent != null) {
			parent.mkdirs();
		}

		int functionLimit = parseLimit(args, 1, 300);
		int stringLimit = parseLimit(args, 2, 300);
		int importLimit = parseLimit(args, 3, 300);

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		JsonWriter writer = new JsonWriter(new FileWriter(outputFile));
		writer.setIndent("  ");

		Listing listing = currentProgram.getListing();
		ReferenceManager refs = currentProgram.getReferenceManager();
		SymbolTable symtab = currentProgram.getSymbolTable();

		Map<String, Symbol> importSymbolsByAddress = new LinkedHashMap<>();
		List<Symbol> collectedImports = new ArrayList<>();
		SymbolIterator externalSymbols = symtab.getExternalSymbols();
		int importTotal = 0;
		while (externalSymbols.hasNext() && !monitor.isCancelled()) {
			Symbol symbol = externalSymbols.next();
			if (symbol.getSymbolType() != SymbolType.FUNCTION) {
				continue;
			}
			importTotal++;
			importSymbolsByAddress.put(symbolKey(symbol), symbol);
			if (collectedImports.size() < importLimit) {
				collectedImports.add(symbol);
			}
		}

		Map<String, Map<String, Object>> stringsByAddress = new LinkedHashMap<>();
		List<Map<String, Object>> collectedStrings = new ArrayList<>();
		int stringTotal = 0;
		for (Data data : DefinedStringIterator.forProgram(currentProgram, currentSelection)) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
			String value = instance.getStringValue();
			if (value == null) {
				continue;
			}
			stringTotal++;
			Map<String, Object> item = stringRef(data, value);
			stringsByAddress.put(addr(data.getAddress()), item);
			if (collectedStrings.size() < stringLimit) {
				collectedStrings.add(item);
			}
		}

		DecompInterface decompiler = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		decompiler.setOptions(options);
		decompiler.openProgram(currentProgram);

		writer.beginObject();
		writer.name("export_schema").value("reverselab-ghidra-summary-v2");

		writer.name("program").beginObject();
		writer.name("name").value(currentProgram.getName());
		writer.name("executable_path").value(currentProgram.getExecutablePath());
		writer.name("format").value(currentProgram.getExecutableFormat());
		writer.name("language").value(currentProgram.getLanguageID().getIdAsString());
		writer.name("compiler_spec").value(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
		writer.name("image_base").value(addr(currentProgram.getImageBase()));
		writer.name("min_address").value(addr(currentProgram.getMinAddress()));
		writer.name("max_address").value(addr(currentProgram.getMaxAddress()));
		writer.endObject();

		writer.name("memory_blocks").beginArray();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			writer.beginObject();
			writer.name("name").value(block.getName());
			writer.name("start").value(addr(block.getStart()));
			writer.name("end").value(addr(block.getEnd()));
			writer.name("size").value(block.getSize());
			writer.name("read").value(block.isRead());
			writer.name("write").value(block.isWrite());
			writer.name("execute").value(block.isExecute());
			writer.name("initialized").value(block.isInitialized());
			writer.endObject();
		}
		writer.endArray();

		int functionTotal = currentProgram.getFunctionManager().getFunctionCount();
		writer.name("functions_total").value(functionTotal);
		writer.name("functions").beginArray();
		int functionCount = 0;
		FunctionIterator functions = listing.getFunctions(true);
		while (functions.hasNext() && !monitor.isCancelled()) {
			Function f = functions.next();
			if (functionCount++ >= functionLimit) {
				break;
			}

			List<Map<String, Object>> importRefs = new ArrayList<>();
			Set<String> seenImports = new LinkedHashSet<>();
			List<Map<String, Object>> stringRefs = new ArrayList<>();
			Set<String> seenStrings = new LinkedHashSet<>();
			InstructionIterator instructions = listing.getInstructions(f.getBody(), true);
			while (instructions.hasNext() && !monitor.isCancelled()) {
				Instruction instruction = instructions.next();
				for (Reference ref : refs.getReferencesFrom(instruction.getAddress())) {
					String to = addr(ref.getToAddress());
					if (importSymbolsByAddress.containsKey(to)) {
						Map<String, Object> item = importRef(importSymbolsByAddress.get(to));
						item.put("from", addr(ref.getFromAddress()));
						item.put("type", ref.getReferenceType().toString());
						addUniqueMap(importRefs, seenImports, to, item, MAX_FUNCTION_IMPORT_REFS);
					}
					if (stringsByAddress.containsKey(to)) {
						Map<String, Object> item = new LinkedHashMap<>(stringsByAddress.get(to));
						item.put("from", addr(ref.getFromAddress()));
						item.put("type", ref.getReferenceType().toString());
						addUniqueMap(stringRefs, seenStrings, to, item, MAX_FUNCTION_STRING_REFS);
					}
				}
			}

			writer.beginObject();
			writer.name("name").value(f.getName());
			writer.name("entry").value(addr(f.getEntryPoint()));
			writer.name("body_size").value(f.getBody().getNumAddresses());
			writer.name("parameter_count").value(f.getParameterCount());
			writer.name("calling_convention").value(f.getCallingConventionName());
			writer.name("thunk").value(f.isThunk());
			writer.name("external").value(f.isExternal());
			writer.name("signature").value(f.getSignature().getPrototypeString(false));
			writer.name("callers").jsonValue(gson.toJson(callersFor(f, refs, MAX_FUNCTION_EDGES)));
			writer.name("callees").jsonValue(gson.toJson(calleesFor(f, refs, listing, MAX_FUNCTION_EDGES)));
			writer.name("import_refs").jsonValue(gson.toJson(importRefs));
			writer.name("string_refs").jsonValue(gson.toJson(stringRefs));
			writer.name("decompile").jsonValue(gson.toJson(decompilePreview(f, decompiler)));
			writer.endObject();
		}
		writer.endArray();
		writer.name("functions_returned").value(Math.min(functionLimit, functionTotal));

		writer.name("imports").beginArray();
		int importCount = 0;
		for (Symbol symbol : collectedImports) {
			List<Map<String, Object>> xrefs = new ArrayList<>();
			Set<String> seen = new LinkedHashSet<>();
			ReferenceIterator iter = refs.getReferencesTo(symbol.getAddress());
			while (iter.hasNext() && xrefs.size() < 32 && !monitor.isCancelled()) {
				Reference ref = iter.next();
				Function fromFunc = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				Map<String, Object> xref = new LinkedHashMap<>();
				xref.put("from", addr(ref.getFromAddress()));
				xref.put("type", ref.getReferenceType().toString());
				xref.put("function", fromFunc == null ? "" : fromFunc.getName());
				xref.put("function_entry", fromFunc == null ? "" : addr(fromFunc.getEntryPoint()));
				addUniqueMap(xrefs, seen, addr(ref.getFromAddress()), xref, 32);
			}
			writer.beginObject();
			writer.name("name").value(symbol.getName());
			writer.name("address").value(addr(symbol.getAddress()));
			writer.name("namespace").value(symbol.getParentNamespace().getName(true));
			writer.name("reference_count").value(symbol.getReferenceCount());
			writer.name("xrefs").jsonValue(gson.toJson(xrefs));
			writer.endObject();
			importCount++;
		}
		writer.endArray();
		writer.name("imports_total").value(importTotal);
		writer.name("imports_returned").value(importCount);

		writer.name("strings").beginArray();
		int stringCount = 0;
		for (Map<String, Object> item : collectedStrings) {
			List<Map<String, Object>> xrefs = new ArrayList<>();
			Set<String> seen = new LinkedHashSet<>();
			Address stringAddress = currentProgram.getAddressFactory().getAddress((String)item.get("address"));
			ReferenceIterator iter = refs.getReferencesTo(stringAddress);
			while (iter.hasNext() && xrefs.size() < 32 && !monitor.isCancelled()) {
				Reference ref = iter.next();
				Function fromFunc = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				Map<String, Object> xref = new LinkedHashMap<>();
				xref.put("from", addr(ref.getFromAddress()));
				xref.put("type", ref.getReferenceType().toString());
				xref.put("function", fromFunc == null ? "" : fromFunc.getName());
				xref.put("function_entry", fromFunc == null ? "" : addr(fromFunc.getEntryPoint()));
				addUniqueMap(xrefs, seen, addr(ref.getFromAddress()), xref, 32);
			}
			writer.beginObject();
			writer.name("address").value((String)item.get("address"));
			writer.name("length").value(((Number)item.get("length")).intValue());
			writer.name("value").value((String)item.get("value"));
			writer.name("xrefs").jsonValue(gson.toJson(xrefs));
			writer.endObject();
			stringCount++;
		}
		writer.endArray();
		writer.name("strings_total").value(stringTotal);
		writer.name("strings_returned").value(stringCount);

		writer.endObject();
		writer.close();
		decompiler.dispose();

		println("ReverseLab summary written to " + outputFile.getAbsolutePath());
	}
}
