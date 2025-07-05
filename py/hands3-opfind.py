# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprMem, ExprId, LocKey
from miasm.arch.x86.regs import *
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from future.utils import viewitems
from argparse import ArgumentParser
from hands3_simple_explore_smt import explore

import sys, z3, os
script_path = os.path.abspath(sys.argv[0])
script_dir = os.path.dirname(script_path)

# 切换工作目录
os.chdir(script_dir)

#filename = '../hands-on3/x-tunnel.bin'
#target_addr = 0x405710
filename = '../hands-on3/anel.bin'
target_addr = 0x1000ABCF
#filename = '../hands-on1/test-add-bcf.bin'
#target_addr = 0x8049170
#filename = '../hands-on1/test-hello-bcf.bin'
#target_addr = 0x8049170
#filename = '../hands-on1/test-mod2-bcf.bin'
#target_addr = 0x08049170
#filename = '../hands-on1/test-mod2-add-bcf.bin'
#target_addr = 0x08049170
#filename = '../hands-on1/test-add-opaque.bin'
#target_addr = 0x08049170
idc = True

def to_idc(lockeys, asmcfg):

    header = '''
#include <idc.idc>
static main(){
'''
    footer = '''
}
'''
    body = ''
    f = open('op-color6.idc', 'w')
    for lbl in lockeys:
        asmblk = asmcfg.loc_key_to_block(lbl)
        if asmblk:
            for l in asmblk.lines:
                body += 'SetColor(0x%08x, CIC_ITEM, 0xc7c7ff);\n'%(l.offset)
    
    f.write(header+body+footer)
    f.close()

loc_db = LocationDB()
with open(filename, 'rb') as fstream:                                      
    cont = Container.from_stream(fstream, loc_db)

machine = Machine('x86_32')
mdis = machine.dis_engine(cont.bin_stream, follow_call=False, loc_db=cont.loc_db)
lifter = machine.lifter_model_call(mdis.loc_db)

# Disassemble the targeted function
asmcfg = mdis.dis_multiblock(target_addr)

# IRCFG
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
for lbl, irblk in viewitems(ircfg.blocks):
    print(irblk)

# Preparing the initial symbols for regs and mems
symbols_init =  {}

# for regs
for i, r in enumerate(all_regs_ids):
    symbols_init[r] = all_regs_ids_init[i]

# for mems
# 0xdeadbeef is the mark to stop the exploring
symbols_init[ExprMem(ExprId('ESP_init', 32), 32)] = ExprInt(0xdeadbeef, 32)

final_states = []

explore(lifter, 
        target_addr, 
        symbols_init, 
        ircfg, 
        lbl_stop=0xdeadbeef, 
        final_states=final_states)
executed_lockey   = []
unexecuted_lockey = []

# The IR nodes which are included in one of paths were executed.
for final_state in final_states:
    if final_state.result:
        for node in final_state.path_history:
            if isinstance(node, int):
                lbl = ircfg.get_loc_key(node)
            elif isinstance(node, ExprInt):
                lbl = ircfg.get_loc_key(node)
            elif isinstance(node, LocKey):
                lbl = node.loc_key

            if lbl not in executed_lockey:
                executed_lockey.append(lbl)
                
# Otherwise, the IR nodes which are not included in any path were not executed.
for lbl, irblock in viewitems(ircfg.blocks):
    if lbl not in executed_lockey:
        unexecuted_lockey.append(lbl)
print(executed_lockey)
print(unexecuted_lockey)
print('len(executed_lockey):', len(executed_lockey))
print('len(unexecuted_lockey):', len(unexecuted_lockey))

# Generate an IDC script to set color on un-executed basic blocks.
if idc:
    to_idc(unexecuted_lockey, asmcfg)
