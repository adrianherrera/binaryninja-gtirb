"""Build a GTIRB module from Binary Ninja."""

from pathlib import Path

import binaryninja as bn
import gtirb

from . import utils


class ModuleBuilder:
    """
    Builds a GTIRB module, representing loadable objects such as executables or
    libraries.
    """

    def __init__(self, bv: bn.BinaryView):
        self._mod = gtirb.Module(
            name=Path(bv.file.filename).name,
            binary_path=bv.file.original_filename,
            isa=utils.to_isa(bv.arch),
            byte_order=utils.to_byte_order(bv.arch),
            file_format=utils.to_file_format(bv.view_type),
            preferred_addr=bv.start,
            rebase_delta=0,
        )
        self._bv = bv

    def build(self) -> gtirb.Module:
        """Build the GTIRB module."""
        self._export_sections()
        self._export_code_blocks()
        self._export_symbols()
        return self._mod

    def _export_sections(self):
        """Export the module sections."""
        for sec in self._bv.sections.values():
            bi = gtirb.ByteInterval(
                address=sec.start,
                size=sec.length,
                contents=self._bv.read(sec.start, sec.length),
            )
            gsec = gtirb.Section(
                name=sec.name,
                byte_intervals=[bi],
                flags=utils.to_section_flags(sec.semantics),
                module=self._mod,
            )
            self._mod.sections.add(gsec)

        utils.log_debug(f"Exported {len(self._mod.sections)} sections")

    def _export_code_blocks(self):
        """Export the module's code."""
        for bb in self._bv.basic_blocks:
            utils.split_blocks_at(
                bb.start, self._mod, force_exec=True, size_hint=bb.length
            )

        self._mod.entry_point = next(
            self._mod.code_blocks_at(self._bv.entry_point), None
        )

        utils.log_debug(f"Exported {len(list(self._mod.code_blocks))} basic blocks")

    def _export_symbols(self):
        """Export the module's symbols."""
        for sym in self._bv.get_symbols():
            data_var = self._bv.get_data_var_at(sym.address)
            if data_var is None:
                continue

            # If the block already exists (e.g., it is a function), just use it.
            # Otherwise, make a new block
            blocks = list(self._mod.byte_blocks_at(sym.address))
            if not blocks:
                blocks = [
                    utils.split_blocks_at(
                        sym.address, self._mod, size_hint=data_var.type.width
                    )
                ]

            for block in blocks:
                gsym = gtirb.Symbol(name=sym.name, payload=block, module=self._mod)
                self._mod.symbols.add(gsym)

        utils.log_debug(f"Exported {len(self._mod.symbols)} symbols")
