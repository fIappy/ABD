# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.expression.expression import *
from miasm.core.utils import *
from miasm.core.locationdb import LocationDB
from miasm.arch.x86 import regs
from miasm.ir.symbexec import SymbolicExecutionEngine, get_block
from miasm.expression.simplifications import expr_simp
import os, sys
script_path = os.path.abspath(sys.argv[0])
script_dir = os.path.dirname(script_path)

# 切换工作目录
os.chdir(script_dir)
class FinalState:
    def __init__(self, result, sym, path_conds, path_history):
        self.result = result
        self.sb = sym
        self.path_conds = path_conds
        self.path_history = path_history

def explore(ir, start_addr, start_symbols, 
        ircfg, cond_limit=30, uncond_limit=100, 
        lbl_stop=None, final_states=[]):

    def codepath_walk(addr, symbols, conds, depth, final_states, path):
    
        if depth >= cond_limit:
            warnings.warn("'depth' is over the cond_limit :%d"%(depth))
            return 

        sb = SymbolicExecutionEngine(ir, symbols)

        for _ in range(uncond_limit):

            if isinstance(addr, ExprInt): 
                if int(addr) == ret_addr:
                    final_states.append(FinalState(True, sb, conds, path))
                    return

            path.append(addr)

            pc = sb.run_block_at(ircfg, addr)

            if isinstance(pc, ExprCond): 
    
                # Calc the condition to take true or false paths
                cond_true  = {pc.cond: ExprInt(1, 32)}
                cond_false = {pc.cond: ExprInt(0, 32)}

                # The destination addr of the true or false paths
                addr_true  = expr_simp(
                    sb.eval_expr(pc.replace_expr(cond_true), {}))

                addr_false = expr_simp(
                    sb.eval_expr(pc.replace_expr(cond_false), {}))

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

# Preparing the initial symbols for regs and mems
symbols_init = dict(regs.regs_init)
initial_symbols = symbols_init.items()

# Prepare VM Semantics
# VM_PC_init and RET_ADDR
vm_pc_init = ExprId('VM_PC_init', 32)
ret_addr = ExprId('RET_ADDR', 32)

infos = {}
infos[expr_simp(ExprMem(regs.ECX_init, 32))] = vm_pc_init
infos[expr_simp(ExprMem(regs.ESP_init-ExprInt(4, 32), 32))] = ret_addr
infos[regs.ESP] = expr_simp(regs.ESP_init-ExprInt(4, 32))

# Virtual registers
for i in range(0, 5):
    infos[expr_simp(ExprMem(regs.ECX_init + ExprInt(4*(i+1), 32), 32))] = ExprId('REG%d' % i, 32)

# Additional info
addition_infos = dict(infos)

# imm
expr_imm8 = expr_simp(ExprMem(vm_pc_init + ExprInt(0x1, 32), 8))
addition_infos[expr_imm8] = ExprId('imm8' , 8)

expr_imm16 = expr_simp(ExprMem(vm_pc_init + ExprInt(0x1, 32), 16))
addition_infos[expr_imm16] = ExprId('imm16' , 16)

expr_imm32 = expr_simp(ExprMem(vm_pc_init + ExprInt(0x1, 32), 32))
addition_infos[expr_imm32] = ExprId('imm32' , 32)

# immb
expr_imm8b = expr_simp(ExprMem(vm_pc_init + ExprInt(0x2, 32), 8))
addition_infos[expr_imm8b] = ExprId('imm8b' , 8)

expr_imm16b = expr_simp(ExprMem(vm_pc_init + ExprInt(0x2, 32), 16))
addition_infos[expr_imm16b] = ExprId('imm16b' , 16)

expr_imm32b = expr_simp(ExprMem(vm_pc_init + ExprInt(0x2, 32), 32))
addition_infos[expr_imm32b] = ExprId('imm32b' , 32)

imms = set([expr_imm8, expr_imm16, expr_imm32,
            expr_imm8b, expr_imm16b, expr_imm32b])

imm8 = ExprId('imm8', 8)

base_regx = expr_simp(regs.ECX_init + (imm8.zeroExtend(32) & ExprInt(0xF, 32)) * ExprInt(4, 32) + ExprInt(0xC, 32))
addition_infos[expr_simp(ExprMem(base_regx, 32))] = ExprId('REGX' , 32)
addition_infos[expr_simp(ExprMem(base_regx, 16))] = ExprId('REGX' , 32)[:16]
addition_infos[expr_simp(ExprMem(base_regx, 8))] = ExprId('REGX' , 32)[:8]

base_regy = expr_simp(regs.ECX_init + (imm8[4:8].zeroExtend(32)) * ExprInt(4, 32) + ExprInt(0xC, 32))
addition_infos[expr_simp(ExprMem(base_regy, 32))] = ExprId('REGY' , 32)
addition_infos[expr_simp(ExprMem(base_regy, 16))] = ExprId('REGY' , 16)[:16]
addition_infos[expr_simp(ExprMem(base_regy, 8))] = ExprId('REGY' , 8)[:8]

def dump_state(sb):
    print('-'*20, 'State', '-'*20)
    out = {}
    for expr, value in sorted(sb.symbols.items()):
        if (expr, value) in initial_symbols:
            continue
        if (expr, value) in addition_infos:
            continue
        if expr in [regs.zf, regs.cf, regs.nf, regs.of, regs.pf, regs.af,
                    ir_arch.IRDst, regs.EIP]:
            continue
        expr_s = expr_simp(expr.replace_expr(addition_infos))
        expr = expr_s
        value = expr_simp(value.replace_expr(addition_infos))
        if expr == value:
            continue
        out[expr] = value

    out = sorted(out.items())
    x86_regs = []
    mem = []
    other = []
    for expr, value in out:
        if expr in regs.all_regs_ids:
            x86_regs.append((expr, value))
        elif isinstance(expr, ExprMem):
            mem.append((expr, value))
        else:
            other.append((expr, value))

    print('Regs:')
    for item in other:
        print('\t%s = %s' % item)
    print('Mem:')
    for item in mem:
        print('\t%s = %s' % item)
    print('x86:')
    for item in x86_regs:
        print('\t%s = %s' % item)
    print('')

filename = '../hands-on5/zeusvm.bin'

machine = Machine('x86_32')
loc_db = LocationDB()
with open(filename, 'rb') as fstream:
    cont = Container.from_stream(fstream, loc_db)
bs = cont.bin_stream
mdis = machine.dis_engine(bs, loc_db=cont.loc_db)
ir_arch = machine.ir(mdis.loc_db)

mnemonic_array_addr = 0x427018

for i in range(69):
    # Get each handler address from the array
    addr = int(hex(upck32(bs.getbytes(mnemonic_array_addr + 4*i, 4))), 16)
    print('*'*40, 'Mnemonic', i, ' addr', hex(addr), '*'*40)
    
    # Generate AsmCFG and IRCFG
    asmcfg = mdis.dis_multiblock(addr)
    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)
    irblock = ircfg.get_block(addr)

    final_states = []
    
    explore(ir_arch, 
            addr, 
            symbols_init, 
            ircfg, 
            final_states=final_states)
    
    # Show results
    print('final states:', len(final_states))

    for final_state in final_states:
        if final_state.result:
            ret_mn = expr_simp(final_state.sb.eval_expr(regs.EAX[:8]))
            if ret_mn != ExprInt(1, 8):
                print('Strange return', ret_mn)
            # Show state after expr_simp
            dump_state(final_state.sb)

        #final_state.sb.dump(ids=False) # Show state before expr_simp
        print('')