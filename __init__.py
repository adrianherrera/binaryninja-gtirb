"""
Binary Ninja plugin for working with the GrammaTech Intermediate Representation
for Binary (GTIRB) format.
"""

import datetime
import time

import binaryninja as bn
import gtirb

from .aux_builder import AuxTables, AuxDataBuilder
from .cfg_builder import CfgBuilder
from .module_builder import ModuleBuilder
from . import utils


class GtirbExporter(bn.BackgroundTaskThread):
    """Export the ``BinaryView`` to GTIRB."""

    def __init__(self, bv: bn.BinaryView, outfile: str, aux_tables: AuxTables):
        """
        Construct a new GTIRB exporter.

        Parameters
        ----------
        bv: binaryninja.BinaryView
            The binary view to export.
        outfile: str
            Path to the exported GTIRB file.
        aux_tables: AuxTables
            The set of auxiliary tables to export.
        """
        bn.BackgroundTaskThread.__init__(
            self, "Exporting binary view to GTIRB", can_cancel=True
        )

        self._bv = bv
        self._outfile = outfile
        self._aux_tables = aux_tables

    def export_to_ir(self) -> gtirb.IR:
        """Export the GTIRB intermediate representation (IR)."""
        self.progress = "Exporting GTIRB module"
        mod = ModuleBuilder(self._bv).build()

        self.progress = "Exporting GTIRB CFG"
        cfg = CfgBuilder(self._bv, mod).build()

        self.progress = "Exporting GTIRB auxiliary tables"
        mod.aux_data = AuxDataBuilder(self._bv, mod, self._aux_tables).build()

        self.progress = "Exporting GTIRB IR"
        return gtirb.IR(modules=[mod], cfg=cfg)

    def run(self):
        start = time.time()
        ir = self.export_to_ir()
        ir.save_protobuf(self._outfile)

        elapsed = time.time() - start
        utils.log_info(
            f"GTIRB successfully exported to {self._outfile} "
            f"(time taken = {datetime.timedelta(seconds=elapsed)})"
        )


def export_gtirb(bv: bn.BinaryView):
    """Plugin entry point."""
    outpath = bn.SaveFileNameField("Exported GTIRB", "gtirb", "out.gtirb")

    aux_table_choices = ["Yes", "No"]
    function_names = bn.ChoiceField("Function Names", aux_table_choices)
    function_entries = bn.ChoiceField("Function Entries", aux_table_choices)
    function_blocks = bn.ChoiceField("Function Blocks", aux_table_choices)
    comments = bn.ChoiceField("Comments", aux_table_choices)
    types = bn.ChoiceField("Types", aux_table_choices)
    libraries = bn.ChoiceField("Libraries", aux_table_choices)
    library_paths = bn.ChoiceField("Library Paths", aux_table_choices)

    flags = {
        AuxTables.FUNCTION_NAMES: function_names,
        AuxTables.FUNCTION_ENTRIES: function_entries,
        AuxTables.FUNCTION_BLOCKS: function_blocks,
        AuxTables.COMMENTS: comments,
        AuxTables.TYPES: types,
        AuxTables.LIBRARIES: libraries,
        AuxTables.LIBRARY_PATHS: library_paths,
    }

    if (
        bn.get_form_input(
            [
                outpath,
                None,
                "Auxiliary Tables",
                function_names,
                function_entries,
                function_blocks,
                comments,
                types,
                libraries,
                library_paths,
            ],
            "GTIRB Export",
        )
        and outpath.result
    ):
        aux_tables = AuxTables(0)
        for flag, choices in flags.items():
            if choices.result == 0:
                aux_tables |= flag
        GtirbExporter(bv, outpath.result, aux_tables).start()


bn.PluginCommand.register("GTIRB\\Export", "Export BNDB as GTIRB", export_gtirb)
