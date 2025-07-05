# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.ir import IRCFG
from miasm.expression.expression import LocKey
from miasm.arch.x86.regs import *
from miasm.core import asmblock
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from future.utils import viewitems
from miasm.ir.translators.translator import Translator
import networkx as nx
import random
import z3, os, sys

script_path = os.path.abspath(sys.argv[0])
script_dir = os.path.dirname(script_path)

# 切换工作目录
os.chdir(script_dir)

#filename = '../hands-on4/vipasana.bin'
#target_addr = 0x434DF0
filename = '../hands-on4/asprox.bin'
target_addr = 0x10009B82
idc = True

def syntax_compare(blk0, blk1):
    if len(blk0.lines) != len(blk1.lines):
        return False

    for l0, l1 in zip(blk0.lines, blk1.lines):
        if str(l0)[0] == 'J':
            instr0 = str(l0).split(' ')[0]
            instr1 = str(l1).split(' ')[0]
            if instr0 != instr1:
                return False
        else:
            if str(l0) != str(l1):
                return False

    return True

def execute_symbolic_execution(src_irb, dst_irb, 
                                lifter0, lifter1, 
                                src_ircfg, dst_ircfg,
                                flag_cmp):

    # Ready for Symbolic Execution
    src_symbols = {}
    dst_symbols = {}

    # regs
    for i, r in enumerate(all_regs_ids):
        src_symbols[r] = all_regs_ids_init[i]
        dst_symbols[r] = all_regs_ids_init[i]


    # Run symbolic execution
    src_sb = SymbolicExecutionEngine(lifter0, src_symbols)

    for assignblk in src_irb:
        skip_update = False
        for dst, src in viewitems(assignblk):
            if str(dst) in ['EIP', 'IRDst']:
                skip_update = True

        if not skip_update:
            src_sb.eval_updt_assignblk(assignblk)

    dst_sb = SymbolicExecutionEngine(lifter1, dst_symbols)

    for assignblk in dst_irb:
        skip_update = False
        for dst, src in viewitems(assignblk):
            if str(dst) in ['EIP', 'IRDst']:
                skip_update = True

        if not skip_update:
            dst_sb.eval_updt_assignblk(assignblk)

    # Equivalence Checking

    src_sb.del_mem_above_stack(lifter0.sp)
    dst_sb.del_mem_above_stack(lifter1.sp)

    all_memory_ids  = [k for k, v in dst_sb.symbols.memory()] + [k for k, v in src_sb.symbols.memory()]

    for k in all_regs_ids + all_memory_ids:

        if str(k) == 'EIP':
            continue

        if not flag_cmp and k in [zf, nf, pf, of, cf, af, df, tf]:
            continue

        v0 = src_sb.symbols[k]
        v1 = dst_sb.symbols[k]

        if v0 == v1:
            continue

        solver = z3.Solver()
        try:
            z3_r_cond = Translator.to_language('z3').from_expr(v0)
        except NotImplementedError:
            return False

        try:
            z3_l_cond = Translator.to_language('z3').from_expr(v1)
        except NotImplementedError:
            return False

        # TODO:
        # Please add just one line of code below to check the equivalence of z3_l_cond and z3_r_cond.
        # Hint: we can add a constraint to 'solver' with 'add' method, e.g., solver.add(A == B).
        # From HERE ------------------------------------------
        solver.add(z3_l_cond != z3_r_cond)
        #solver.add()

        # TO HERE ------------------------------------------

        r = solver.check()
        if r == z3.unsat:
            continue

        else:
            #print(solver.model()) # Counterexample
            return False

    return True

def semantic_compare(blk0, blk1, lifter0, lifter1, asmcfg, flag_cmp=False):
    src_ircfg = IRCFG(None, lifter0.loc_db)
    try:
        lifter0.add_asmblock_to_ircfg(blk0, src_ircfg)
    except NotImplementedError:
        return False

    dst_ircfg = IRCFG(None, lifter1.loc_db)
    try:
        lifter1.add_asmblock_to_ircfg(blk1, dst_ircfg)
    except NotImplementedError:
        return False

    if len(src_ircfg.blocks) != len(dst_ircfg.blocks):
        return False
    for src_lbl, dst_lbl in zip(src_ircfg.blocks, dst_ircfg.blocks):

        src_irb = src_ircfg.blocks.get(src_lbl, None)
        dst_irb = dst_ircfg.blocks.get(dst_lbl, None)

        r = execute_symbolic_execution(
                            src_irb, dst_irb, 
                            lifter0, lifter1, 
                            src_ircfg, dst_ircfg,
                            flag_cmp)
        if r is False:
            return False

    return True


loc_db = LocationDB()
with open(filename, 'rb') as fstream:                                      
    cont = Container.from_stream(fstream, loc_db)
    
machine = Machine('x86_32')
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
lifter0 = machine.lifter_model_call(mdis.loc_db)
lifter1 = machine.lifter_model_call(mdis.loc_db)

asmcfg = mdis.dis_multiblock(target_addr)

target_blocks = []
for cn, block in enumerate(asmcfg.blocks):
    target_blocks.append(block)

results = {}

for src_blk in target_blocks:
    src_ldl = src_blk._loc_key

    # Skip a basic block containing only single instruction
    if len(src_blk.lines) == 1 and src_blk.lines[0].dstflow():
        continue

    for dst_blk in target_blocks:
        dst_ldl = dst_blk._loc_key

        # Skip a basic block containing only single instruction
        if len(dst_blk.lines) == 1 and dst_blk.lines[0].dstflow():
            continue

        if src_ldl == dst_ldl:
            continue

        if (src_ldl, dst_ldl) in results.keys() or \
            (dst_ldl, src_ldl) in results.keys():
            continue
        
        r_syntax = syntax_compare(src_blk, dst_blk)

        if r_syntax:
            # If the syntax of two blocks is same, then the semantics of them is also same.
            r_semantic = True
        else:
            # Otherwise, need to compare the semantics of them
            r_semantic = semantic_compare(src_blk, dst_blk, lifter0, lifter1, asmcfg)

        results[(src_ldl, dst_ldl)] = [(r_syntax, r_semantic)]

if idc:
    G = nx.Graph()
    G.add_nodes_from(target_blocks)

    for k, v in viewitems(results):
        if v[0][0] or v[0][1]:
            G.add_edge(k[0], k[1])

    # Return a list containing randomlly generated colors
    def gen_random_color():

        ret = []

        r = [x for x in range(256)]
        g = [x for x in range(256)]
        b = [x for x in range(256)]
        random.shuffle(r)
        random.shuffle(g)
        random.shuffle(b)

        for a2, a1, a0 in zip(r,g,b):
            color = a2 << 16 | a1 << 8 | a0
            ret.append(color)

        return ret

    random_colors = gen_random_color()
    body = ''

    for n, conn_nodes in enumerate(nx.connected_components(G)):

        if len(conn_nodes) == 1:
            continue

        for node in conn_nodes: # node is asmblk

            if isinstance(node, LocKey):
                asmblk = asmcfg.loc_key_to_block(node)
                if asmblk:
                    for l in asmblk.lines:
                        body += 'SetColor(0x%08x, CIC_ITEM, 0x%x);\n'%(l.offset, random_colors[n])
            else:
                for l in node.lines:
                    body += 'SetColor(0x%08x, CIC_ITEM, 0x%x);\n'%(l.offset, random_colors[n])
        
    header = '''
#include <idc.idc>
static main()
{
'''
    footer = '''
}
'''

    f = open('asprox-color.idc', 'w')
    f.write(header+body+footer)
    f.close()