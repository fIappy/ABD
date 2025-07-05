from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.jitter.llvmconvert import *
from llvmlite import ir as llvm_ir

from miasm.expression.simplifications import expr_simp_high_to_explicit
from miasm.analysis.cst_propag import propagate_cst_expr
from miasm.analysis.data_flow import DeadRemoval, merge_blocks, remove_empty_assignblks
from miasm.ir.ir import IntermediateRepresentation, AssignBlock
from future.utils import viewitems, viewvalues
from argparse import ArgumentParser
from miasm.core.locationdb import LocationDB
loc_db = LocationDB()
arg = 0
if arg:
    parser = ArgumentParser("MIASM IR to LLVM to X86 Optimizer")
    parser.add_argument("target", help="Target binary")
    parser.add_argument("addr", help="Target address")
    parser.add_argument("--architecture", "-a", help="Force architecture")
    args = parser.parse_args()
    fd = open(args.target, 'rb')
    addr = int(args.addr, 16)
    filename = args.target
    print(hex(addr), filename)

else:
    filename = './hands-on1/test-add-sub.bin'
    fd = open(filename, 'rb')
    addr = 0x08049170

# Opening Target File and storing it in a 'Container' object
cont = Container.from_stream(fd, loc_db=loc_db)

# Instantiating Disassembler
machine = Machine(cont.arch)
lifter = machine.lifter_model_call(loc_db)

dis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)

# Disassembling and extracting CFG
asmcfg = dis.dis_multiblock(addr)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# Printing IR before simplification
print('Before Simplification:')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)


# Simplifying 
deadrm = DeadRemoval(lifter)
#entry_points = set([dis.loc_db.get_offset_location(args.addr)])
init_infos = lifter.arch.regs.regs_init
cst_propag_link = propagate_cst_expr(lifter, ircfg, addr, init_infos)
deadrm(ircfg)
remove_empty_assignblks(ircfg)
ircfg.simplify(expr_simp_high_to_explicit)


modified = True
while modified:
    modified = False
    modified |= deadrm(ircfg)
    modified |= remove_empty_assignblks(ircfg)

# Printing IR After simplification
print('After Simplification:')
i = 0
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)
    print(len(irb))

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


to_obj(lifter, ircfg, filename, addr)