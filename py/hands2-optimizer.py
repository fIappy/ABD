# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.analysis.cst_propag import propagate_cst_expr
from miasm.analysis.data_flow import DeadRemoval, merge_blocks, remove_empty_assignblks
from miasm.core.locationdb import LocationDB
from future.utils import viewitems

filename = './hands-on1/test-add-sub.bin'
addr = 0x08049170

loc_db = LocationDB()
machine = Machine('x86_32')
cont = Container.from_stream(open(filename, 'rb'), loc_db)
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
lifter = machine.lifter_model_call(mdis.loc_db)

asmcfg = mdis.dis_multiblock(addr)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

print('Before Simplification:')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)

init_infos = lifter.arch.regs.regs_init
cst_propag_link = propagate_cst_expr(lifter, ircfg, hex(addr), init_infos)
deadrm = DeadRemoval(lifter)

modified = True
while modified:
    modified = False
    modified |= deadrm(ircfg)
    modified |= remove_empty_assignblks(ircfg)

print('After Simplification:')

for lbl, irb in viewitems(ircfg.blocks):
    print(irb)