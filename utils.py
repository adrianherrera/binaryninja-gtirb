"""Utilities for converting between Binary Ninja and GTIRB."""

from typing import Mapping, Optional, Set

import binaryninja as bn
import gtirb


def log_alert(text: str, logger: str = "GTIRB"):
    """Wrapper around Binary Ninja's __alert__ log."""
    bn.log_alert(text, logger)


def log_debug(text: str, logger: str = "GTIRB"):
    """Wrapper around Binary Ninja's __debug__ log."""
    bn.log_debug(text, logger)


def log_error(text: str, logger: str = "GTIRB"):
    """Wrapper around Binary Ninja's __error__ log."""
    bn.log_error(text, logger)


def log_info(text: str, logger: str = "GTIRB"):
    """Wrapper around Binary Ninja's __info__ log."""
    bn.log_info(text, logger)


def log_warn(text: str, logger: str = "GTIRB"):
    """Wrapper around Binary Ninja's __warn__ log."""
    bn.log_warn(text, logger)


def to_byte_order(arch: bn.Architecture) -> gtirb.Module.ByteOrder:
    """Get the GTIRB byte order from the Binary Ninja architecture."""
    byte_order = gtirb.Module.ByteOrder.Undefined
    if arch.endianness == bn.Endianness.BigEndian:
        byte_order = gtirb.Module.ByteOrder.Big
    elif arch.endianness == bn.Endianness.LittleEndian:
        byte_order = gtirb.Module.ByteOrder.Little

    return byte_order


def to_isa(arch: bn.Architecture) -> gtirb.Module.ISA:
    """Get the GTIRB ISA from the Binary Ninja architecture."""
    isa = gtirb.Module.ISA.Undefined
    if arch.name in ("aarch64",):
        isa = gtirb.Module.ISA.ARM64
    elif arch.name in ("armv7", "thumb2", "armv7eb", "thumb2eb"):
        isa = gtirb.Module.ISA.ARM
    elif arch.name in ("mipsel32", "mips32"):
        isa = gtirb.Module.ISA.MIPS32
    elif arch.name in ("mips64",):
        isa = gtirb.Module.ISA.MIPS64
    elif arch.name in ("ppc", "ppc_le"):
        isa = gtirb.Module.ISA.PPC32
    elif arch.name in ("ppc64", "ppc64_le"):
        isa = gtirb.Module.ISA.PPC64
    elif arch.name in ("x86",):
        isa = gtirb.Module.ISA.IA32
    elif arch.name in ("x86_64",):
        isa = gtirb.Module.ISA.X64

    return isa


def to_file_format(view_type: str) -> gtirb.Module.FileFormat:
    """Get the GTIRB file format from the Binary Ninja view type."""
    file_format = gtirb.Module.FileFormat.Undefined
    if view_type.lower() == "elf":
        file_format = gtirb.Module.FileFormat.ELF
    elif view_type.lower() == "pe":
        file_format = gtirb.Module.FileFormat.PE
    elif view_type.lower() == "mapped":
        file_format = gtirb.Module.FileFormat.RAW
    elif view_type.lower() == "mach-o":
        file_format = gtirb.Module.FileFormat.MACHO
    elif view_type.lower() == "coff":
        file_format = gtirb.Module.FileFormat.COFF

    return file_format


def to_section_flags(semantics: bn.SectionSemantics) -> Set[gtirb.Section.Flag]:
    """Get the GTIRB flags from the Binary Ninja section semantics."""
    flags: Set[gtirb.Section.Flag] = set()

    if semantics == bn.SectionSemantics.ReadOnlyCodeSectionSemantics:
        flags.add(gtirb.Section.Flag.Executable)
        flags.add(gtirb.Section.Flag.Readable)
    elif semantics == bn.SectionSemantics.ReadOnlyDataSectionSemantics:
        flags.add(gtirb.Section.Flag.Readable)
    elif semantics == bn.SectionSemantics.ReadWriteDataSectionSemantics:
        flags.add(gtirb.Section.Flag.Readable)
        flags.add(gtirb.Section.Flag.Writable)

    return flags


def to_edge_label(edge: bn.BasicBlockEdge) -> gtirb.EdgeLabel:
    """Get the GTIRB edge label from the Binary Ninja basic block edge."""
    edge_label = None
    if edge.fall_through:
        edge_label = gtirb.EdgeLabel(
            gtirb.EdgeType.Fallthrough, conditional=False, direct=True
        )
    elif edge.type == bn.BranchType.CallDestination:
        edge_label = gtirb.EdgeLabel(
            gtirb.EdgeType.Call, conditional=False, direct=True
        )
    elif edge.type == bn.BranchType.FunctionReturn:
        edge_label = gtirb.EdgeLabel(
            gtirb.EdgeType.Return, conditional=False, direct=True
        )
    elif edge.type == bn.BranchType.SystemCall:
        edge_label = gtirb.EdgeLabel(
            gtirb.EdgeType.Syscall, conditional=False, direct=True
        )
    elif edge.type == bn.BranchType.TrueBranch:
        edge_label = gtirb.EdgeLabel(
            gtirb.EdgeType.Branch, conditional=True, direct=True
        )
    elif edge.type in (
        bn.BranchType.FalseBranch,
        bn.BranchType.ExceptionBranch,
        bn.BranchType.UnconditionalBranch,
        bn.BranchType.UserDefinedBranch,
    ):
        edge_label = gtirb.EdgeLabel(
            gtirb.EdgeType.Branch, conditional=False, direct=True
        )
    elif edge.type in (bn.BranchType.IndirectBranch, bn.BranchType.UnresolvedBranch):
        edge_label = gtirb.EdgeLabel(
            gtirb.EdgeType.Branch, conditional=False, direct=False
        )

    assert edge_label, f"Unknown edge type {edge.type}"
    return edge_label


def address_to_block_map(mod: gtirb.Module) -> Mapping[int, gtirb.Block]:
    """Create dictionary to aid in the lookup of blocks by address."""
    d: Mapping[int, gtirb.Block] = {}
    for sec in mod.sections:
        for bi in sec.byte_intervals:
            for block in bi.blocks:
                if block.address is not None:
                    d[block.address] = block

    return d


def split_blocks_at(
    address: int,
    mod: gtirb.Module,
    force_exec: bool = False,
    size_hint: int = 0,
) -> Optional[gtirb.ByteBlock]:
    """
    Get a block that starts at the specified address, splitting to make
    a new block if necessary.

    Parameters
    ----------
    address: int
        Address to split block at.
    mod: gtirb.Module
        GTIRB module containing the block.
    force_exec: bool, default False
        Force the block to be a ``gtirb.CodeBlock``. Otherwise, determine if the
        block is a ``gtirb.CodeBlock`` or ``gtirb.DataBlock`` depending on
        whether the container ``gtirb.Section`` is an executable or data
        section.
    size_hint: int, default 0
        Desired size of the block. The size hint may be ignored (e.g., if the
        block will not fit).

    Returns
    -------
    A block if one can be found/made, ``None`` otherwise.
    """
    sec: Optional[gtirb.Section] = None
    bi: Optional[gtirb.ByteInterval] = None
    new_block_offset = 0

    for cur_section in mod.sections:
        for cur_interval in cur_section.byte_intervals:
            interval_addr = cur_interval.address
            if interval_addr is None:
                continue

            new_block_offset = address - interval_addr
            if 0 <= new_block_offset < cur_interval.size:
                sec = cur_section
                bi = cur_interval
                break
        if bi:
            break

    if not bi:
        return None

    is_exec = gtirb.Section.Flag.Executable in sec.flags
    if force_exec and not is_exec:
        log_info(f"Skipping non-executable CodeBlock: {sec.name} {address:#0x}")
        return None

    # Find the matching block in this ByteInterval
    block_index = 0
    old_block = None
    old_block_size = 0
    old_block_offset = 0

    for block in bi.blocks:
        block_size = block.size
        old_block_offset = block.offset

        # Block boundary matches what we need without splitting
        if new_block_offset == old_block_offset:
            return block

        # Check whether the new block should fill a gap between
        # existing blocks
        if new_block_offset < old_block_offset:
            break

        block_index += 1

        # Check if this is the block we need to split
        if new_block_offset - old_block_offset < block_size:
            old_block = block
            old_block_size = block_size
            break

    # Split this block to make a new block that starts at the desired address
    decode_mode = gtirb.CodeBlock.DecodeMode.Default
    if old_block:
        # Splitting an old block, keeping its offset but shrinking to fit a
        # new block after it
        prev_size = new_block_offset - old_block_offset
        new_size = old_block_size - prev_size
        is_exec = isinstance(old_block, gtirb.CodeBlock)
        old_block.size = prev_size
        if is_exec:
            decode_mode = old_block.decode_mode
    elif new_block_offset >= old_block_offset:
        # Adding a new block in empty space at the of the ByteInterval
        new_size = bi.size - new_block_offset
    else:
        # Adding a new block in empty space. old_block_offset here refers
        # to the **next** block
        new_size = old_block_offset - new_block_offset

    if size_hint > new_size:
        # Ignore the size hint if we can't fit a block that large here
        log_warn(
            "Unable to add a block that would overlap another block at "
            f"{sec.name}: {new_block_offset:#0x}"
        )
    elif size_hint > 0:
        new_size = size_hint

    if is_exec:
        if (
            mod.isa in (gtirb.Module.ISA.ARM, gtirb.Module.ISA.ARM64)
            and new_block_offset % 2 != 0
        ):
            decode_mode = gtirb.CodeBlock.DecodeMode.Thumb
        new_block = gtirb.CodeBlock(
            decode_mode=decode_mode,
            size=new_size,
            offset=new_block_offset,
            byte_interval=bi,
        )
    else:
        new_block = gtirb.DataBlock(
            size=new_size, offset=new_block_offset, byte_interval=bi
        )

    bi.blocks.add(new_block)
    return new_block
