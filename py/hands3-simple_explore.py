# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprCond, ExprId, ExprInt, ExprMem 
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.regs import *
from miasm.core import parse_asm, asmblock
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from future.utils import viewitems
from miasm.loader.strpatchwork import *
from miasm.ir.translators.translator import Translator
import warnings
import z3

class FinalState:
    def __init__(self, result, sym, path_conds, path_history):
        self.result = result
        self.sb = sym
        self.path_conds = path_conds
        self.path_history = path_history



def explore(lifter, start_addr, start_symbols, 
        ircfg, cond_limit=30, uncond_limit=100, 
        lbl_stop=None, final_states=[]):

    def codepath_walk(addr, symbols, conds, depth, final_states, path):

        if depth >= cond_limit:
            warnings.warn("'depth' is over the cond_limit :%d"%(depth))
            return 

        sb = SymbolicExecutionEngine(lifter, symbols)

        for _ in range(uncond_limit):

            if isinstance(addr, ExprInt):
                if int(addr) == lbl_stop:
                    final_states.append(FinalState(True, sb, conds, path))
                    return

            path.append(addr)

            pc = sb.run_block_at(ircfg, addr)

            if isinstance(pc, ExprCond): 
    
                # Calc the condition to take true or false paths
                cond_true  = {pc.cond: ExprInt(1, 32)}
                cond_false = {pc.cond: ExprInt(0, 32)}

                # The destination addr of the true or false paths
                addr_true  = expr_simp(pc.replace_expr(cond_true))
                assert addr_true == pc.src1
                addr_false = expr_simp(pc.replace_expr(cond_false))
                assert addr_false == pc.src2
                # Need to add the path conditions to reach this point
                conds_true = list(conds) + list(cond_true.items())
                conds_false = list(conds) + list(cond_false.items())

                # Recursive call for the true or false path
                codepath_walk(
                        addr_true, sb.symbols.copy(), 
                        conds_true, depth + 1, final_states, list(path))

                codepath_walk(
                        addr_false, sb.symbols.copy(), 
                        conds_false, depth + 1, final_states, list(path))

                return
            else:
                addr = expr_simp(sb.eval_expr(pc))

        final_states.append(FinalState(True, sb, conds, path))
        return 

    return codepath_walk(start_addr, start_symbols, [], 0, final_states, [])

# Assemble code
loc_db = LocationDB()
asmcfg = parse_asm.parse_txt(mn_x86, 32, ''' 
main:
    PUSH EBP
    MOV EBP, ESP
    MOV ECX, 0x23
    MOV EDX, EAX
    MUL EDX
    CMP EAX, -1
    JNZ label
    MOV DWORD PTR [0xDEADBEEF], ECX

label:
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
    print('%08x'%(offset), mn_x86.dis(raw, 32))

cont = Container.from_string(array_tobytes(patch_worker.s), loc_db)

machine = Machine('x86_32')
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

asmcfg2 = mdis.dis_multiblock(0)

lifter = machine.lifter_model_call(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg2)

#for lbl, irb in viewitems(ircfg.blocks):
#    print(irb)
#
symbols_init =  {
    ExprMem(ExprId('ESP_init', 32), 32) : ExprInt(0xdeadbeef, 32)
}

for i, r in enumerate(all_regs_ids):
    symbols_init[r] = all_regs_ids_init[i]

final_states = []

explore(lifter, 
        0, 
        symbols_init, 
        ircfg, 
        lbl_stop=0xdeadbeef, 
        final_states=final_states)


# Show results
print('final states:', len(final_states))

for final_state in final_states:
    if final_state.result:
        print('Feasible path:','->'.join([str(x) for x in final_state.path_history]))
        print('\t',final_state.path_conds)
    else:
        print('Infeasible path:','->'.join([str(x) for x in final_state.path_history]))
        print('\t',final_state.path_conds)

    final_state.sb.dump(ids=False)
    print('')

