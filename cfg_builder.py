"""Build a GTIRB control-flow graph (CFG) from Binary Ninja."""

from collections import defaultdict
from typing import Iterable, Mapping, Optional, Set
import itertools

import binaryninja as bn
import gtirb

from . import utils


class CfgBuilder:
    """
    Builds an interprocedural control-flow graph (ICFG).
    """

    def __init__(self, bv: bn.BinaryView, mod: gtirb.Module):
        self._bv = bv
        self._mod = mod
        self._addr_to_block = utils.address_to_block_map(mod)
        self._cfg = gtirb.CFG()

    def build(self) -> gtirb.CFG:
        """Build the ICFG."""
        ret_sites: Mapping[bn.Function, Set[gtirb.CfgNode]] = defaultdict(set)

        for func in self._bv.functions:
            # Build the interprocedural control flow graph between functions.
            # Possible indirect call sites are determined via the function's
            # LLIL.
            #
            # To adhere to the ICFG "rules" (described at
            # https://grammatech.github.io/gtirb/md__c_f_g-_edges.html) we split
            # the basic block at the call site and insert a "fall through" edge
            # from the original block (ending with the call instruction) to the
            # new block (starting with the instruction following the call
            # instruction).
            for cs in func.call_sites:
                # Get all possible callee addresses.
                #
                # XXX Sometimes callsites are identified where there's no call.
                # Skip this "call site" if that happens
                callees = self._get_callees(cs)
                if callees is None:
                    continue

                # Get the Binary Ninja basic block at the call site
                bb = func.get_basic_block_at(cs.address)

                # Get the code blocks at the call site
                caller_blocks = list(self._mod.code_blocks_on(cs.address))
                assert caller_blocks

                # A call is only direct if it has one possible callee
                is_direct = len(callees) == 1 and callees[0] is not None

                # If the call is not the last instruction in the basic block,
                # split the block. This will make a new "successor" block
                # starting at the instruction following the call. Otherwise, the
                # successor blocks are the intraprocedural successor blocks.
                succ_addr = cs.address + self._bv.get_instruction_length(cs.address)
                if succ_addr < bb.end:
                    succ_block = utils.split_blocks_at(
                        succ_addr,
                        self._mod,
                        force_exec=True,
                        size_hint=bb.end - succ_addr,
                    )

                    # Update the block map with the new block
                    self._addr_to_block[succ_addr] = succ_block

                    # Resize the original caller blocks
                    for block in caller_blocks:
                        block.size = succ_addr - block.address

                    # Only a single successor block: the newly split block
                    succ_blocks = [succ_block]
                else:
                    # Potentially multiple successor blocks: the blocks
                    # connected by outgoing branches
                    succ_blocks = [
                        self._addr_to_block[e.target.start] for e in bb.outgoing_edges
                    ]

                # Used to determine if a fallthrough edge is required after the
                # caller block
                need_fall_through = False

                # Add call edges from the caller block to the callee entry
                # blocks. There may be multiple callees when an indirect call is
                # made (and we can only generate a set of possible callees)
                for callee in callees:
                    # If we don't have a CFG node for the callee address then
                    # this is an indirect call (and we use a proxy block)
                    callee_block = self._addr_to_block.get(
                        callee, gtirb.ProxyBlock(module=self._mod)
                    )
                    have_callee = not isinstance(callee_block, gtirb.ProxyBlock)
                    if not have_callee:
                        is_direct = False

                        # The call is indirect, so we don't know anything about
                        # the callee function. Be conservative and assume it
                        # returns and thus requires a fall through edge.
                        need_fall_through = True

                    for block in caller_blocks:
                        edge = gtirb.Edge(
                            block,
                            callee_block,
                            gtirb.EdgeLabel(
                                conditional=False,
                                direct=is_direct,
                                type=gtirb.EdgeType.Call,
                            ),
                        )
                        self._cfg.add(edge)

                    # Use the binary ninja function to work out return info (if
                    # we know the callee). In particular, if the callee function
                    # can return, then we need to add return edges from the
                    # callee's return sites to the successor block (i.e., the
                    # block following the call). We may also need to add a fall
                    # through edge from the caller basic block to its successor
                    # (per https://grammatech.github.io/gtirb/md__c_f_g-_edges.html#autotoc_md26)
                    if have_callee:
                        callee_func = self._bv.get_function_at(callee)
                        if callee_func.can_return:
                            need_fall_through = True
                            for block in succ_blocks:
                                ret_sites[callee_func].add(block)

                # Add a fall through edge from the caller block to the successor
                # blocks (i.e, to the instruction following the call). If none
                # of the callees can return, then we don't need any fall through
                # edges.
                if need_fall_through:
                    for dst in succ_blocks:
                        for src in caller_blocks:
                            edge = gtirb.Edge(
                                src,
                                dst,
                                gtirb.EdgeLabel(
                                    conditional=False,
                                    direct=True,
                                    type=gtirb.EdgeType.Fallthrough,
                                ),
                            )
                            self._cfg.add(edge)

            # Now that blocks have been split, add intraprocedural edges for
            # this function. Do this based on the LLIL
            for bb in func.llil:
                # Get the code block containing the intraprocedural branch
                # instruction (which will always be the last instruction in the
                # basic block)
                branch_blocks = list(self._mod.code_blocks_on(bb[-1].address))

                # Add branch edges
                for e in bb.outgoing_edges:
                    dst = self._addr_to_block[e.target.source_block.start]
                    for src in branch_blocks:
                        edge = gtirb.Edge(src, dst, utils.to_edge_label(e))
                        self._cfg.add(edge)

        # Add interprocedural return edges from return sites back to the
        # instruction following the call (per
        # https://grammatech.github.io/gtirb/md__c_f_g-_edges.html#autotoc_md28).
        # Because we previosuly split the call site block, this will be the
        # start of a new block
        for func in self._bv.functions:
            for ret in self._get_returns(func):
                for ret_site in ret_sites[func]:
                    edge = gtirb.Edge(
                        ret,
                        ret_site,
                        gtirb.EdgeLabel(
                            conditional=False, direct=True, type=gtirb.EdgeType.Return
                        ),
                    )
                    self._cfg.add(edge)

        utils.log_debug(f"Exported CFG with {len(self._cfg)} edges")
        return self._cfg

    def _get_callees(
        self, call_site: bn.ReferenceSource
    ) -> Optional[Iterable[Optional[int]]]:
        """
        Get all possible destination addresses (callees) from the given call
        site.
        """
        # Find the call instruction at the given call site. Sometimes there's no
        # actual call here, in which case we just bail early
        call = next(
            (
                inst
                for inst in call_site.function.get_llils_at(call_site.address)
                if isinstance(inst, bn.Call)
            ),
            None,
        )
        if call is None:
            return None

        callee_addrs = call.dest.possible_values

        # Collect the CFG nodes corresponding to the possible callee sites. In
        # addition to the CFG nodes, we also track whether the call is a direct
        # or indirect call. It is direct if there is only one possible callee
        # address. It is indirect if the possible callee site is unknown or
        # there are multiple callee sites.
        dests: Iterable[Optional[int]]

        if callee_addrs.type in (
            bn.RegisterValueType.ConstantValue,
            bn.RegisterValueType.ConstantPointerValue,
        ):
            dests = [callee_addrs.value]
        elif callee_addrs.type == bn.RegisterValueType.InSetOfValues:
            dests = callee_addrs.values
        else:
            dests = [None]

        return dests

    def _get_returns(self, func: bn.Function) -> Iterable[gtirb.CfgNode]:
        """Get the CFG nodes that return from a function."""
        return itertools.chain.from_iterable(
            self._mod.code_blocks_on(bb[-1].address)
            for bb in func.llil.basic_blocks
            if isinstance(bb[-1], bn.Return)
        )
