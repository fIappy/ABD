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
from miasm.expression.simplifications import expr_simp_high_to_explicit
from miasm.expression.simplifications import expr_simp, ExpressionSimplifier

from miasm.jitter.llvmconvert import *
from llvmlite import ir as llvm_ir

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
    
cont = Container.from_string(array_tobytes(patch_worker.s), loc_db=loc_db)
print("patch_worker:", patch_worker.s)
machine = Machine('x86_32')
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
asmcfg2 = mdis.dis_multiblock(0)
lifter = machine.lifter_model_call(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg2)
print('Before Simplification:')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)
#deadrm = DeadRemoval(lifter)
#deadrm(ircfg)
#remove_empty_assignblks(ircfg)
ircfg.simplify(expr_simp_high_to_explicit)


print('After Simplification:')

for lbl, irb in viewitems(ircfg.blocks):
    print(irb)



def to_obj(lifter, ircfg, filename, addr):


    # Instantiate an LLVM context and Function to fill
    context = LLVMContext_IRCompilation()
    context.lifter = lifter

    func = LLVMFunction_IRCompilation(context, name="test")
    func.ret_type = llvm_ir.VoidType()
    func.init_fc()

    # Initializing Registers for LLVM mock Function (needed to export function)
    all_regs = set()
    for block in viewvalues(ircfg.blocks):
        for irs in block.assignblks:
            for dst, src in viewitems(irs.get_rw(mem_read=True)):
                elem = src.union(set([dst]))
                all_regs.update(
                    x for x in elem
                    if x.is_id()
                )

    for var in all_regs:
        data = context.mod.globals.get(str(var), None)
        if data is None:
            data = llvm_ir.GlobalVariable(context.mod,  LLVMType.IntType(var.size), name=str(var))
        data.initializer = LLVMType.IntType(var.size)(0)
        func.local_vars_pointers[var.name] = func.builder.alloca(llvm_ir.IntType(var.size), name=var.name)
        print(var.name)
        if var.name in ("ESP", "EBP"):
            value = func.builder.load(data)
            func.builder.store(value, func.local_vars_pointers[var.name])

    # IRCFG is imported, without the final "ret void"
    func.from_ircfg(ircfg, append_ret=False)

    # Finish the function
    func.builder.ret_void()

    # Extract LLVM IR if needed
    #open("out.ll", "w").write(str(func))
    print(str(func))
    # Parsing LLVM IR
    M = llvm.parse_assembly(str(func))
    M.verify()

    # Initialising Native Exporter
    llvm.initialize()
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()

    # Optimisation to clean value computation
    pmb = llvm.create_pass_manager_builder()
    pmb.opt_level = 2
    pm = llvm.create_module_pass_manager()
    pmb.populate(pm)
    pm.run(M)

    # Generate Binary output
    target = llvm.Target.from_default_triple()
    target = target.from_triple('i386-pc-linux-gnu')
    target_machine = target.create_target_machine()
    obj_bin = target_machine.emit_object(M)
    obj = llvm.ObjectFileRef.from_data(obj_bin)
    open("./%s-%s.o" % (filename, hex(addr)), "wb").write(obj_bin)


to_obj(lifter, ircfg, "test_unremoval2", 0)



# jitter to confirm that the branch is not actually taken
def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True

myjit = Machine('x86_32').jitter(loc_db, 'gcc')
myjit.init_stack()
run_addr = 0x00000000
myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, array_tobytes(patch_worker.s))
print("patch_worker:", patch_worker.s)

myjit.set_trace_log()
myjit.push_uint32_t(0x1337beef)
myjit.add_breakpoint(0x1337beef, code_sentinelle)
myjit.init_run(run_addr)
myjit.continue_run()