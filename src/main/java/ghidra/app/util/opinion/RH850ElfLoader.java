/* SPDX-License-Identifier: MIT */
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;

/**
 * The ELF loader, restricted to V850/RH850 files and to this module's languages.
 * <p>
 * Ghidra's own V850 module and this one both claim EM_V800 / EM_V850 / EM_CYGNUS_V850 in their
 * opinions, so the generic ELF loader offers two preferred languages: the import dialog then
 * pre-selects none, and a headless import takes whichever comes first in a hash set. This
 * loader has its own opinion entries (v850.opinion, which lists only RH850 languages for it) and
 * sorts just before the generic ELF loader, so it is the default loader for these files and
 * its single preferred language is the default language. Loading is the generic ELF loader's
 * (the program's executable format is still ELF).
 */
public class RH850ElfLoader extends ElfLoader {

	public static final String RH850_ELF_NAME = "Executable and Linking Format (ELF) for RH850/V850";

	private static final Set<Short> MACHINES = Set.of((short) 36, (short) 87, (short) 0x9080);

	@Override
	public String getName() {
		return RH850_ELF_NAME;
	}

	@Override
	public int getTierPriority() {
		return super.getTierPriority() - 1;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		try {
			ElfHeader elf = new ElfHeader(provider, null);
			if (!MACHINES.contains(elf.e_machine())) {
				return List.of();
			}
		}
		catch (ElfException e) {
			return List.of();
		}
		List<LoadSpec> specs = new ArrayList<>();
		for (LoadSpec spec : super.findSupportedLoadSpecs(provider)) {
			if (spec.getLanguageCompilerSpec() != null && spec.getLanguageCompilerSpec()
					.getLanguageID()
					.getIdAsString()
					.startsWith("RH850:")) {
				specs.add(spec);
			}
		}
		return specs;
	}
}
