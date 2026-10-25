/* SPDX-License-Identifier: MIT */
package ghidra.app.plugin.core.analysis;

import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * GCC's out-of-line prologue and epilogue helpers (libgcc lib1funcs.S, -mprolog-function):
 * <ul>
 * <li>{@code __save_*} is called with "jarl __save_*, r10" and returns with "jmp [r10]". That
 * jump gets a RETURN flow override, so the helper decompiles as a function instead of an
 * unrecovered computed jump. Any function entered through "jarl f, r10" whose code jumps
 * through r10 is treated the same way.</li>
 * <li>The cspec has a call fixup for every helper (tools/gen_callfixups.py), which Ghidra
 * attaches by name. In images without symbols the helpers are recognised by their code (the
 * stack adjustment and which register goes to which slot) and get the fixup of the matching
 * name, so callers decompile with their frame and saved registers instead of helper calls.</li>
 * </ul>
 */
public class RH850PrologueHelperAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RH850 GCC Prologue Helpers";
	private static final String DESCRIPTION =
		"Makes \"jmp [r10]\" in functions called through \"jarl f, r10\" (GCC's __save_* " +
			"helpers) a return, and attaches the __save_*/__return_* call fixups to the " +
			"helpers of images without symbols.";

	/** helper name (without __save_/__return_) -> registers in slot order (lp = r31) */
	static final Map<String, List<String>> VARIANTS = new LinkedHashMap<>();
	static {
		for (String top : new String[] { "r29", "r31" }) {
			List<Integer> lows = new ArrayList<>(List.of(2));
			for (int r = 20; r < 30; r++) {
				lows.add(r);
			}
			if (top.equals("r31")) {
				lows.add(31);
			}
			for (int low : lows) {
				List<String> regs = new ArrayList<>();
				String name;
				if (top.equals("r29") && low == 29) {
					name = "r29";
					regs.add("r29");
				}
				else if (low == 31) {
					name = "r31";
				}
				else {
					name = "r" + low + "_" + top;
					for (int r = 29; r >= Math.max(low, 20); r--) {
						regs.add("r" + r);
					}
					if (low == 2) {
						regs.add("r2");
					}
				}
				if (top.equals("r31")) {
					regs.add("lp");
				}
				VARIANTS.put(name, regs);
			}
		}
	}

	public RH850PrologueHelperAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("RH850"));
	}

	private static boolean isReg(Object o, String name) {
		return o instanceof Register r && r.getName().equals(name);
	}

	private static Register reg(Instruction ins, int op) {
		Object[] o = ins.getOpObjects(op);
		return o.length == 1 && o[0] instanceof Register r ? r : null;
	}

	/** memory operand "off[base]": the offset, if the base is sp, or ep when ep = sp */
	private static Long slot(Instruction ins, int op, boolean epIsSp) {
		Long off = null;
		boolean base = false;
		for (Object o : ins.getOpObjects(op)) {
			if (o instanceof Scalar s) {
				off = s.getUnsignedValue();
			}
			else if (isReg(o, "sp") || (epIsSp && isReg(o, "ep"))) {
				base = true;
			}
		}
		return base ? (off == null ? 0L : off) : null;
	}

	/**
	 * Recognises a helper from its code: returns "__save_X" / "__return_X" for a body that does
	 * exactly what the fixup of that name does, or null.
	 */
	static String recognise(Program program, Address entry) {
		Instruction ins = program.getListing().getInstructionAt(entry);
		Map<Long, String> slots = new HashMap<>();
		long adjust = 0;
		boolean epIsSp = false, store = false, load = false;
		for (int i = 0; ins != null && i < 24; i++, ins = ins.getNext()) {
			String m = ins.getMnemonicString();
			if (m.equals("addi") && isReg(ins.getOpObjects(1).length == 1 ? ins.getOpObjects(1)[0] : null, "sp") &&
				"sp".equals(reg(ins, 2) == null ? null : reg(ins, 2).getName())) {
				Scalar s = ins.getScalar(0);
				if (s == null) {
					return null;
				}
				adjust += s.getSignedValue();
			}
			else if (m.equals("mov") && reg(ins, 0) != null && reg(ins, 1) != null) {
				String a = reg(ins, 0).getName(), b = reg(ins, 1).getName();
				if (a.equals("sp") && b.equals("ep")) {
					epIsSp = true;
				}
				else if (!(a.equals("ep") && b.equals("r1")) && !(a.equals("r1") && b.equals("ep"))) {
					return null;
				}
			}
			else if ((m.equals("st.w") || m.equals("sst.w")) && reg(ins, 0) != null) {
				Long off = slot(ins, 1, epIsSp);
				if (off == null || load) {
					return null;
				}
				slots.put(off, reg(ins, 0).getName());
				store = true;
			}
			else if ((m.equals("ld.w") || m.equals("sld.w")) && reg(ins, 1) != null) {
				Long off = slot(ins, 0, epIsSp);
				if (off == null || store) {
					return null;
				}
				slots.put(off, reg(ins, 1).getName());
				load = true;
			}
			else if (m.equals("jmp")) {
				Register t = reg(ins, 0);
				String kind = store && t != null && t.getName().equals("r10") && adjust < 0 ? "save"
						: load && t != null && t.getName().equals("lp") && adjust > 0 ? "return"
								: null;
				if (kind == null) {
					return null;
				}
				for (Map.Entry<String, List<String>> v : VARIANTS.entrySet()) {
					List<String> regs = v.getValue();
					if (Math.abs(adjust) != 4L * regs.size() || slots.size() != regs.size()) {
						continue;
					}
					boolean same = true;
					for (int k = 0; k < regs.size() && same; k++) {
						same = regs.get(k).equals(slots.get(4L * k));
					}
					if (same) {
						return "__" + kind + "_" + v.getKey();
					}
				}
				return null;
			}
			else {
				return null;
			}
		}
		return null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		PcodeInjectLibrary lib = program.getCompilerSpec().getPcodeInjectLibrary();
		Set<Address> saves = new HashSet<>(), returns = new HashSet<>();
		InstructionIterator it = listing.getInstructions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction ins = it.next();
			String m = ins.getMnemonicString();
			Address[] flows = ins.getFlows();
			if (flows.length != 1) {
				continue;
			}
			if (m.equals("jarl") && ins.getNumOperands() == 2 && isReg(reg(ins, 1), "r10")) {
				saves.add(flows[0]);
			}
			else if (m.equals("jr")) {
				returns.add(flows[0]);
			}
		}
		for (Address a : saves) {
			monitor.checkCancelled();
			// the helper returns through r10: make its "jmp [r10]" a return
			Instruction ins = listing.getInstructionAt(a);
			for (int i = 0; ins != null && i < 32; i++, ins = ins.getNext()) {
				FlowType ft = ins.getFlowType();
				if (ins.getMnemonicString().equals("jmp") && isReg(reg(ins, 0), "r10")) {
					if (ins.getFlowOverride() != FlowOverride.RETURN) {
						ins.setFlowOverride(FlowOverride.RETURN);
					}
					break;
				}
				if (!ft.isFallthrough() || ft.isCall()) {
					break;
				}
			}
			if (fm.getFunctionAt(a) == null) {
				new CreateFunctionCmd(a).applyTo(program, monitor);
			}
			attachFixup(program, lib, a);
		}
		for (Address a : returns) {
			monitor.checkCancelled();
			if (recognise(program, a) != null) {
				if (fm.getFunctionAt(a) == null) {
					new CreateFunctionCmd(a).applyTo(program, monitor);
				}
				attachFixup(program, lib, a);
			}
		}
		return true;
	}

	private static void attachFixup(Program program, PcodeInjectLibrary lib, Address a) {
		Function f = program.getFunctionManager().getFunctionAt(a);
		if (f == null || f.getCallFixup() != null) {
			return;
		}
		String name = recognise(program, a);
		if (name != null && lib.getPayload(InjectPayload.CALLFIXUP_TYPE, name) != null) {
			f.setCallFixup(name);
		}
	}
}
