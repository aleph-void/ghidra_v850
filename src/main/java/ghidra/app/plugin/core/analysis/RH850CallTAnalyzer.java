/* SPDX-License-Identifier: MIT */
package ghidra.app.plugin.core.analysis;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves CALLT targets (upstream issue #20). CALLT imm6 calls CTBP + (halfword at CTBP +
 * imm6 * 2); CTBP is a system register that start-up code sets once, so the call is indirect.
 * The analyzer takes CTBP from the "CTBP" analysis option or from an "ldsr rX, CTBP" whose rX
 * is loaded with a constant just before (mov imm32, movhi/movea, or movea from r0), gives every
 * CALLT a call-override reference to its target, and disassembles the target and makes it a
 * function. (ghidra_scripts/RH850CallT.java does the same on demand.)
 */
public class RH850CallTAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RH850 CALLT Targets";
	private static final String DESCRIPTION =
		"Resolves CALLT calls through the CALLT table at CTBP (found from \"ldsr rX, CTBP\" or " +
			"given as an option) and makes the targets functions.";
	private static final String OPTION_CTBP = "CTBP (0 = find it from ldsr)";

	private long ctbpOption = 0;

	public RH850CallTAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("RH850"));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_CTBP, 0L, null,
			"Value of CTBP, the CALLT table base, when the program does not set it with a " +
				"constant (0: find it)");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		ctbpOption = options.getLong(OPTION_CTBP, 0L);
	}

	private static Long scalar(Instruction ins, int op) {
		Scalar s = ins.getScalar(op);
		return s == null ? null : s.getSignedValue();
	}

	/** value loaded into reg by the instructions just before 'at' (mov imm32 / movhi + movea) */
	static Long constantBefore(Instruction at, Register reg) {
		Long lo = null;
		Instruction ins = at.getPrevious();
		for (int i = 0; i < 6 && ins != null; i++, ins = ins.getPrevious()) {
			String m = ins.getMnemonicString();
			Object[] dst = ins.getOpObjects(ins.getNumOperands() - 1);
			if (dst.length != 1 || !reg.equals(dst[0])) {
				continue;
			}
			if (m.equals("mov") && ins.getLength() == 6) {
				return scalar(ins, 0) & 0xffffffffL;
			}
			if (m.equals("movea") && lo == null) {
				lo = scalar(ins, 0);
				Object[] base = ins.getOpObjects(1);
				if (lo != null && base.length == 1 && base[0] instanceof Register r &&
					r.getName().equals("r0")) {
					return lo & 0xffffffffL;
				}
				Object[] src = ins.getOpObjects(1);
				if (src.length == 1 && src[0] instanceof Register r) {
					reg = r; // movea lo, rY, rX: the high part was loaded into rY
				}
				continue;
			}
			if (m.equals("movhi") && lo != null) {
				Long hi = scalar(ins, 0);
				return hi == null ? null : ((hi << 16) + lo) & 0xffffffffL;
			}
			return null;
		}
		return null;
	}

	static Long findCtbp(Program program) {
		InstructionIterator it = program.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getMnemonicString().equals("ldsr") && ins.toString().contains("CTBP")) {
				Object[] src = ins.getOpObjects(0);
				if (src.length == 1 && src[0] instanceof Register r) {
					Long v = constantBefore(ins, r);
					if (v != null) {
						return v;
					}
				}
			}
		}
		return null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		List<Instruction> callts = new ArrayList<>();
		InstructionIterator it = program.getListing().getInstructions(set, true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getMnemonicString().equals("callt") &&
				ins.getOperandReferences(0).length == 0) {
				callts.add(ins);
			}
		}
		if (callts.isEmpty()) {
			return true;
		}
		Long ctbp = ctbpOption != 0 ? ctbpOption : findCtbp(program);
		if (ctbp == null) {
			log.appendMsg(NAME, "CTBP not found; " + callts.size() +
				" CALLT calls stay indirect (set the CTBP analysis option)");
			return true;
		}
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		for (Instruction ins : callts) {
			monitor.checkCancelled();
			Long idx = scalar(ins, 0);
			if (idx == null) {
				continue;
			}
			Address target;
			try {
				int off = program.getMemory().getShort(space.getAddress(ctbp + idx * 2)) & 0xffff;
				target = space.getAddress(ctbp + off);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				continue;
			}
			if (!program.getMemory().getExecuteSet().contains(target) &&
				program.getMemory().getBlock(target) == null) {
				continue;
			}
			ins.addOperandReference(0, target, RefType.CALL_OVERRIDE_UNCONDITIONAL,
				SourceType.ANALYSIS);
			if (program.getListing().getInstructionAt(target) == null) {
				new DisassembleCommand(target, null, true).applyTo(program, monitor);
			}
			if (program.getFunctionManager().getFunctionAt(target) == null) {
				new CreateFunctionCmd(target).applyTo(program, monitor);
			}
		}
		return true;
	}
}
