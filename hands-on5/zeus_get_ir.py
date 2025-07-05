from argparse import ArgumentParser
from pdb import pm

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.ir.symbexec import symbexec
from miasm2.arch.x86.sem import ir_x86_32
from miasm2.arch.x86 import regs
from miasm2.core.utils import *
from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp
from miasm2.ir.ir import AssignBlock
from miasm2.core.asmbloc import expr_is_int_or_label
from miasm2.core import asmbloc


# Transform native assembly into IR
def get_block(ir_arch, mdis, ad):
    mdis.job_done.clear()
    lbl = ir_arch.get_label(ad)
    if not lbl in ir_arch.blocs:
        b = mdis.dis_bloc(lbl.offset)
        ir_arch.add_bloc(b)
    b = ir_arch.get_bloc(lbl)
    if b is None:
        raise LookupError('No block found at that address: %s' % lbl)
    return b

parser = ArgumentParser("Disassemble a binary")
parser.add_argument('filename', help="File to disassemble")
args = parser.parse_args()

machine = Machine("x86_32")
cont = Container.from_stream(open(args.filename))
bs = cont.bin_stream
mdis = machine.dis_engine(bs, symbol_pool=cont.symbol_pool)
ir_arch = ir_x86_32(mdis.symbol_pool)


symbols_init = dict(regs.regs_init)

initial_symbols = symbols_init.items()
ret_addr = ExprId('RET_ADDR')
vm_pc_init = ExprId('VM_PC_init')
infos = {}
infos[expr_simp(ExprMem(regs.ECX_init, 32))] = vm_pc_init
# Push return addr
infos[expr_simp(ExprMem(regs.ESP_init-ExprInt32(4)))] = ret_addr
infos[regs.ESP] = expr_simp(regs.ESP_init-ExprInt32(4))

for i in xrange(0, 5):
    infos[expr_simp(ExprMem(regs.ECX_init + ExprInt32(4*(i+1)), 32))] = ExprId("REG%d" % i, 32)

addition_infos = dict(infos)

# imm
expr_imm8 = expr_simp(ExprMem(vm_pc_init + ExprInt32(0x1), 8))
addition_infos[expr_imm8] = ExprId("imm8" , 8)

expr_imm16 = expr_simp(ExprMem(vm_pc_init + ExprInt32(0x1), 16))
addition_infos[expr_imm16] = ExprId("imm16" , 16)

expr_imm32 = expr_simp(ExprMem(vm_pc_init + ExprInt32(0x1), 32))
addition_infos[expr_imm32] = ExprId("imm32" , 32)

# immb
expr_imm8b = expr_simp(ExprMem(vm_pc_init + ExprInt32(0x2), 8))
addition_infos[expr_imm8b] = ExprId("imm8b" , 8)

expr_imm16b = expr_simp(ExprMem(vm_pc_init + ExprInt32(0x2), 16))
addition_infos[expr_imm16b] = ExprId("imm16b" , 16)

expr_imm32b = expr_simp(ExprMem(vm_pc_init + ExprInt32(0x2), 32))
addition_infos[expr_imm32b] = ExprId("imm32b" , 32)

imms = set([expr_imm8, expr_imm16, expr_imm32,
            expr_imm8b, expr_imm16b, expr_imm32b])

imm8 = ExprId('imm8', 8)
#imm8 = ExprId('imm8XXX', 8)
#imm8 = expr_imm8
# (ECX_init+(({@8[(VM_PC_init+0x1)],0,8, 0x0,8,32}&0xF)*0x4)+0xC)
base_regx = expr_simp(regs.ECX_init + (imm8.zeroExtend(32) & ExprInt32(0xF)) * ExprInt32(4) + ExprInt32(0xC))
addition_infos[expr_simp(ExprMem(base_regx, 32))] = ExprId("REGX" , 32)
addition_infos[expr_simp(ExprMem(base_regx, 16))] = ExprId("REGX" , 32)[:16]
addition_infos[expr_simp(ExprMem(base_regx, 8))] = ExprId("REGX" , 32)[:8]

base_regy = expr_simp(regs.ECX_init + (imm8[4:8].zeroExtend(32)) * ExprInt32(4) + ExprInt32(0xC))
addition_infos[expr_simp(ExprMem(base_regy, 32))] = ExprId("REGY" , 32)
addition_infos[expr_simp(ExprMem(base_regy, 16))] = ExprId("REGY" , 16)[:16]
addition_infos[expr_simp(ExprMem(base_regy, 8))] = ExprId("REGY" , 8)[:8]


mnemonic_array_addr = 0x427018



def dump_state(sb):
    print '-'*20, "State", '-'*20
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

    out = sorted(out.iteritems())
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

    print "Regs:"
    for item in other:
        print "\t%s = %s" % item
    print "Mem:"
    for item in mem:
        print "\t%s = %s" % item
    #print "x86:"
    #for item in x86_regs:
    #    print "\t%s = %s" % item
    print


for i in xrange(69):
    ad = ExprInt32(upck32(bs.getbytes(mnemonic_array_addr +4*i, 4)))

    sb = symbexec(ir_arch, symbols_init)
    for k, v in infos.iteritems():
        sb.symbols[k] = v

    print '*'*40, 'Mnemonic', i, ' addr', ad, '*'*40

    symbols = frozenset(sb.symbols.items())
    todo = set([(ad, symbols)])

    count = 20
    while todo and count > 0:
        count -=1
        ad, symbols = todo.pop()
        if not get_block(ir_arch, mdis, ad):
            raise ValueError("Unknown destination %s" % ad)


        sb.symbols.symbols_id.clear()
        sb.symbols.symbols_mem.clear()
        for k, v in symbols:
            sb.symbols[k] = v

        print 'Block', ad
        get_block(ir_arch, mdis, ad)
        ad = sb.emul_ir_bloc(ir_arch, ad)

        sb.del_mem_above_stack(ir_arch.sp)

        if ad is ret_addr:
            print "Ret addr reached"
            ret_mn = expr_simp(sb.eval_expr(regs.EAX[:8]))
            if ret_mn != ExprInt(1, 8):
                print "Strange return", ret_mn
            dump_state(sb)
            continue

        if isinstance(ad, ExprCond):
            todo.add((ad.src1, frozenset(sb.symbols.items())))
            todo.add((ad.src2, frozenset(sb.symbols.items())))
            continue
        if not expr_is_int_or_label(ad):
            print "BAD END", ad
            break
        todo.add((ad, frozenset(sb.symbols.items())))
    if count == 0:
        print 'Mnemonic too complex'


