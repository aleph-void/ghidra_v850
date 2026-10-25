// Resolves CALLT targets. CALLT imm6 calls CTBP + (halfword at CTBP + imm6 * 2); CTBP is a
// system register set once at start-up, so the decompiler sees an unknown indirect call.
// This script finds CTBP (from "ldsr rX, CTBP" preceded by a constant load of rX, or from the
// script argument), adds a call-override reference from every CALLT to its target and creates
// the target functions.
//   script argument (optional): CTBP value in hex
//@category RH850

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class RH850CallT extends GhidraScript {

	private Long scalar(Instruction ins, int op) {
		Scalar s = ins.getScalar(op);
		return s == null ? null : s.getSignedValue();
	}

	// value loaded into reg by the instructions just before 'at' (mov imm32 / movhi + movea)
	private Long constantBefore(Instruction at, Register reg) {
		Long hi = null, lo = null;
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
				if (base.length == 1 && base[0] instanceof Register r && r.getName().equals("r0")) {
					return lo & 0xffffffffL;
				}
				continue;
			}
			if (m.equals("movhi") && lo != null) {
				hi = scalar(ins, 0);
				return ((hi << 16) + lo) & 0xffffffffL;
			}
			return null;
		}
		return null;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		Long ctbp = args.length > 0 ? Long.parseLong(args[0].replace("0x", ""), 16) : null;
		List<Instruction> callts = new ArrayList<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			String m = ins.getMnemonicString();
			if (m.equals("callt")) {
				callts.add(ins);
			}
			else if (ctbp == null && m.equals("ldsr") && ins.toString().contains("CTBP")) {
				Object[] src = ins.getOpObjects(0);
				if (src.length == 1 && src[0] instanceof Register r) {
					ctbp = constantBefore(ins, r);
				}
			}
		}
		if (ctbp == null) {
			println("RH850CallT: CTBP not found; pass its value as the script argument");
			return;
		}
		int n = 0;
		for (Instruction ins : callts) {
			long idx = scalar(ins, 0);
			Address entry = toAddr(ctbp + idx * 2);
			int off = getShort(entry) & 0xffff;
			Address target = toAddr(ctbp + off);
			ins.addOperandReference(0, target, RefType.CALL_OVERRIDE_UNCONDITIONAL,
				SourceType.USER_DEFINED);
			if (getInstructionAt(target) == null) {
				new DisassembleCommand(target, null, true).applyTo(currentProgram, monitor);
			}
			if (getFunctionAt(target) == null) {
				createFunction(target, null);
			}
			n++;
		}
		println(String.format("RH850CallT: CTBP = 0x%x, %d CALLT sites resolved", ctbp, n));
	}
}
