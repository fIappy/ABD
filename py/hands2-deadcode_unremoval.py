# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm, asmblock
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from future.utils import viewitems
from miasm.loader.strpatchwork import *
from miasm.analysis.data_flow import *
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
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


loc_db.set_location_offset(loc_db.get_name_location('main'), 0x0)

patches = asmblock.asm_resolve_final(mn_x86, asmcfg)
patch_worker = StrPatchwork()
for offset, raw in patches.items():
    patch_worker[offset] = raw

cont = Container.from_string(array_tobytes(patch_worker.s), loc_db=loc_db)
machine = Machine('x86_32')


def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True



mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
asmcfg2 = mdis.dis_multiblock(0)
lifter = machine.lifter_model_call(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg2)

print('Before Simplification:')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)

deadrm = DeadRemoval(lifter)
deadrm(ircfg)


print('After Simplification:')

for lbl, irb in viewitems(ircfg.blocks):
    print(irb)

myjit = Machine('x86_32').jitter(loc_db, 'gcc')
myjit.init_stack()
run_addr = 0x40000000
myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, array_tobytes(patch_worker.s))
myjit.set_trace_log()
myjit.push_uint32_t(0x1337beef)
myjit.add_breakpoint(0x1337beef, code_sentinelle)
myjit.run(run_addr)

