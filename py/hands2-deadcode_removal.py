# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm
from miasm.core.locationdb import LocationDB
from future.utils import viewitems
from miasm.analysis.data_flow import DeadRemoval
import pydotplus
from IPython.display import Image, display_png

loc_db = LocationDB()

asmcfg = parse_asm.parse_txt(mn_x86, 32, ''' 
main:
    PUSH EBP
    MOV EBP, ESP
    MOV ECX, 0x23
    MOV ECX, 0x4
    MOV EAX, ECX
    POP EBP
    RET
''', loc_db)
loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)

machine = Machine('x86_32')
lifter = machine.lifter_model_call(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

print('Before Simplification:')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)
deadrm = DeadRemoval(lifter)
deadrm(ircfg)

print('After Simplification:')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)
