"""Build GTIRB AuxData tables from Binary Ninja."""

from enum import Flag, auto
from collections import defaultdict
from typing import Mapping, Optional, Set
from uuid import UUID

import binaryninja as bn
import gtirb

from . import utils


class AuxTables(Flag):
    """Determine which auxiliary tables to export."""

    FUNCTION_NAMES = auto()
    FUNCTION_ENTRIES = auto()
    FUNCTION_BLOCKS = auto()
    COMMENTS = auto()
    TYPES = auto()
    LIBRARIES = auto()
    LIBRARY_PATHS = auto()


class AuxDataBuilder:
    """Builds several auxiliary data tables."""

    def __init__(
        self, bv: bn.BinaryView, mod: gtirb.Module, tables_to_export: AuxTables
    ):
        self._bv = bv
        self._mod = mod
        self._tables_to_export = tables_to_export

    def build(self) -> Mapping[str, gtirb.AuxData]:
        """Build a set of auxiliary data tables."""
        aux_tables = {}

        if self._tables_to_export & (
            AuxTables.FUNCTION_NAMES
            | AuxTables.FUNCTION_ENTRIES
            | AuxTables.FUNCTION_BLOCKS
        ):
            aux_tables |= self._export_function_tables()
        if (AuxTables.COMMENTS in self._tables_to_export) and (
            comments := self._export_comments()
        ):
            aux_tables["comments"] = comments
        if (AuxTables.TYPES in self._tables_to_export) and (
            types := self._export_types()
        ):
            aux_tables["types"] = types
        if (AuxTables.LIBRARIES in self._tables_to_export) and (
            libs := self._export_libraries()
        ):
            aux_tables["libraries"] = libs
        if (AuxTables.LIBRARY_PATHS in self._tables_to_export) and (
            lib_paths := self._export_library_paths()
        ):
            aux_tables["libraryPaths"] = lib_paths

        return aux_tables

    def _find_first_symbol(self, name: str) -> Optional[gtirb.Symbol]:
        """Find the first symbol with the given name."""
        return next(self._mod.symbols_named(name), None)

    def _export_function_tables(self) -> Mapping[str, gtirb.AuxData]:
        """
        Export the ``functionNames``, ``funtionEntries``, and ``functionBlocks``
        auxiliary tables.
        """
        function_names: Mapping[UUID, UUID] = {}
        function_entries: Mapping[UUID, Set[UUID]] = defaultdict(set)
        function_blocks: Mapping[UUID, Set[UUID]] = {}

        for func in self._bv.functions:
            func_node = gtirb.Node()

            # Function name
            if (AuxTables.FUNCTION_NAMES in self._tables_to_export) and (
                sym := self._find_first_symbol(func.name)
            ):
                function_names[func_node.uuid] = sym.uuid

            # Function entry
            if AuxTables.FUNCTION_ENTRIES in self._tables_to_export:
                for block in self._mod.code_blocks_at(func.start):
                    function_entries[func_node.uuid].add(block.uuid)

            # Function blocks
            if AuxTables.FUNCTION_BLOCKS in self._tables_to_export:
                blocks = set(
                    block.uuid
                    for bb in func.basic_blocks
                    for block in self._mod.code_blocks_at(bb.start)
                )
                if blocks:
                    function_blocks[func_node.uuid] = blocks

        # Make auxiliary tables
        ret: Mapping[str, gtirb.AuxData] = {}
        if function_names:
            utils.log_debug(
                f"Exported functionNames table with {len(function_names)} entries"
            )
            ret["functionNames"] = gtirb.AuxData(
                data=function_names, type_name="mapping<UUID,UUID>"
            )
        if function_entries:
            utils.log_debug(
                f"Exported functionEntries table with {len(function_entries)} entries"
            )
            ret["functionEntries"] = gtirb.AuxData(
                data=function_entries, type_name="mapping<UUID,set<UUID>>"
            )
        if function_blocks:
            utils.log_debug(
                f"Exported functionBlocks table with {len(function_blocks)} entries"
            )
            ret["functionBlocks"] = gtirb.AuxData(
                data=function_blocks, type_name="mapping<UUID,set<UUID>>"
            )

        return ret

    def _export_comments(self) -> Optional[gtirb.AuxData]:
        """Export the ``comments`` auxiliary table."""
        comments: Mapping[int, str] = {
            # Comments attached to data
            **self._bv.address_comments,
            # Comments attached to code (i.e., functions)
            **{
                addr: comment
                for func in self._bv.functions
                for addr, comment in func.comments.items()
            },
        }

        addr_to_blocks = utils.address_to_block_map(self._mod)
        gcomments: Mapping[gtirb.Offset, str] = {}

        for addr, comment in comments.items():
            block = addr_to_blocks.get(addr)
            if block is None or not block.address:
                continue
            displacement = addr - block.address
            offset = gtirb.Offset(element_id=block, displacement=displacement)
            gcomments[offset] = comment

        if not gcomments:
            return None

        utils.log_debug(f"Exported comments aux table with {len(gcomments)} entries")
        return gtirb.AuxData(data=gcomments, type_name="mapping<Offset,string>")

    def _export_types(self) -> Optional[gtirb.AuxData]:
        """Export the ``types`` auxiliary table."""
        types: Mapping[UUID, str] = {}
        type_printer = bn.TypePrinter.default

        for sym in self._bv.get_symbols():
            v = self._bv.get_data_var_at(sym.address)
            if v is None:
                continue
            for block in self._mod.data_blocks_at(sym.address):
                types[block.uuid] = type_printer.get_type_string(v.type)

        if not types:
            return None

        utils.log_debug(f"Exported types aux table with {len(types)} entries")
        return gtirb.AuxData(data=types, type_name="mapping<UUID,string>")

    def _export_libraries(self) -> Optional[gtirb.AuxData]:
        """Export the ``libraries`` auxiliary table."""
        libs = [lib.name for lib in self._bv.get_external_libraries()]

        if not libs:
            return None

        utils.log_debug(f"Exported libraries aux table with {len(libs)} entries")
        return gtirb.AuxData(data=libs, type_name="sequence<string>")

    def _export_library_paths(self) -> Optional[gtirb.AuxData]:
        """Export the ``libraryPaths`` auxiliary table."""
        lib_paths = [lib.backing_file for lib in self._bv.get_external_libraries()]

        if not lib_paths or all(p is None for p in lib_paths):
            return None

        utils.log_debug(
            f"Exported libraryPaths aux table with {len(lib_paths)} entries"
        )
        return gtirb.AuxData(data=lib_paths, type_name="sequence<string>")
