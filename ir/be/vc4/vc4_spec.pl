# the cpu architecture (ia32, ia64, mips, sparc, ppc, ...)
$arch = "vc4";

#
# Modes
#
$mode_gp  = "vc4_mode_gp"; # mode used by general purpose registers

# The node description is done as a perl hash initializer with the
# following structure:
#
# %nodes = (
#
# <op-name> => {
#   state     => "floats|pinned|mem_pinned|exc_pinned", # optional
#   comment   => "any comment for constructor",  # optional
#   in_reqs   => [ "reg_class|register" ] | "...",
#   out_reqs  => [ "reg_class|register|in_rX" ] | "...",
#   outs      => { "out1", "out2" },# optional, creates pn_op_out1, ... consts
#   ins       => { "in1", "in2" },  # optional, creates n_op_in1, ... consts
#   mode      => "mode_Iu",         # optional, predefines the mode
#   emit      => "emit code with templates",   # optional for virtual nodes
#   attr      => "additional attribute arguments for constructor", # optional
#   init_attr => "emit attribute initialization template",         # optional
#   rd_constructor => "c source code which constructs an ir_node", # optional
#   hash_func => "name of the hash function for this operation",   # optional, get the default hash function else
#   latency   => "latency of this operation (can be float)"        # optional
#   attr_type => "name of the attribute struct",                   # optional
# },
#
# ... # (all nodes you need to describe)
#
# ); # close the %nodes initializer

# state: state of the operation, OPTIONAL (default is "floats")
#
# arity: arity of the operation, MUST NOT BE OMITTED
#
# outs:  if a node defines more than one output, the names of the projections
#        nodes having outs having automatically the mode mode_T
#
# comment: OPTIONAL comment for the node constructor
%reg_classes = (
	gp => [
		{ name => "r0" },
		{ name => "r1" },
		{ name => "r2" },
		{ name => "r3" },
		{ name => "r4" },
		{ name => "r5" },
		{ name => "r6" },
		{ name => "r7" },
		{ name => "r8" },
		{ name => "r9" },
		{ name => "r10" },
		{ name => "r11" },
		{ name => "r12" },
		{ name => "r13" },
		{ name => "r14" },
		{ name => "r15" },
		{ name => "r16" },
		{ name => "r17" },
		{ name => "r18" },
		{ name => "r19" },
		{ name => "r20" },
		{ name => "r21" },
		{ name => "r22" },
		{ name => "r23" },
		{ name => "dp" },  # data pointer
		{ name => "sp"  }, # stack pointer
		{ name => "lr"  }, # link register
		{ name => "r27" },
		{ name => "esp" }, # exception/interrupt stack pointer
		{ name => "r29" },
		{ name => "sr" },  # status register
		{ mode => $mode_gp }
	],
);

$default_attr_type = "vc4_attr_t";
$default_copy_attr = "vc4_copy_attr";

my $binop = {
	irn_flags => [ "rematerializable" ],
	in_reqs   => [ "gp", "gp" ],
	out_reqs  => [ "gp" ],
	mode      => $mode_gp,
};

my $constop = {
	op_flags   => [ "constlike" ],
	irn_flags  => [ "rematerializable" ],
	out_reqs   => [ "gp" ],
	mode       => $mode_gp,
};

my $unop = {
	irn_flags => [ "rematerializable" ],
	in_reqs   => [ "gp" ],
	out_reqs  => [ "gp" ],
	mode      => $mode_gp,
};

%nodes = (

# Integer nodes

Add => {
	template => $binop,
	emit     => '%D0 = add %S0, %S1',
},

Mul => {
	template => $binop,
	emit     => '%D0 = mul %S0, %S1',
},

And => {
	template => $binop,
	emit     => '%D0 = and %S0, %S1',
},

Or => {
	template => $binop,
	emit     => '%D0 = or %S0, %S1',
},

Xor => {
	template => $binop,
	emit     => '%D0 = xor %S0, %S1',
},

Sub => {
	template => $binop,
	emit     => '%D0 = sub %S0, %S1',
},

Shl => {
	template => $binop,
	emit     => '%D0 = shl %S0, %S1',
},

Shr => {
	template => $binop,
	emit     => '%D0 = shr %S0, %S1',
},

Minus => {
	template => $unop,
	emit     => '%D0 = neg %S0',
},

Not => {
	template => $unop,
	emit     => '%D0 = not %S0',
},

Const => {
	template   => $constop,
	attr       => "ir_tarval *value",
	custominit => "set_vc4_value(res, value);",
	emit       => '%D0 = const %I',
},

Address => {
	template   => $constop,
	attr       => "ir_entity *entity",
	custominit => "set_vc4_entity(res, entity);",
	emit       => '%D0 = address of %E',
},

# Control Flow

Jmp => {
	state     => "pinned",
	op_flags  => [ "cfopcode" ],
	irn_flags => [ "simple_jump" ],
	out_reqs  => [ "none" ],
	mode      => "mode_X",
},

Start => {
	irn_flags => [ "schedule_first" ],
	state     => "pinned",
	out_reqs  => "...",
	ins       => [],
	emit      => "",
},

Return => {
	state    => "pinned",
	op_flags => [ "cfopcode" ],
	in_reqs  => "...",
	out_reqs => [ "none" ],
	ins      => [ "mem", "stack", "first_result" ],
	outs     => [ "X" ],
	mode     => "mode_X",
},

# Load / Store

Load => {
	op_flags  => [ "uses_memory" ],
	irn_flags => [ "rematerializable" ],
	state     => "exc_pinned",
	in_reqs   => [ "none", "gp" ],
	out_reqs  => [ "gp", "none" ],
	ins       => [ "mem", "ptr" ],
	outs      => [ "res", "M" ],
	emit      => '%D0 = load (%S1)',
},

Ld => {
	op_flags  => [ "uses_memory" ],
	state     => "exc_pinned",
	ins       => [ "ptr", "mem" ],
	outs      => [ "res", "M" ],
	in_reqs   => [ "gp", "none" ],
	out_reqs  => [ "gp", "none" ],
	emit      => 'ld %D0, %o(%S0)',
},

Store => {
	op_flags  => [ "uses_memory" ],
	irn_flags => [ "rematerializable" ],
	state     => "exc_pinned",
	in_reqs   => [ "none", "gp", "gp" ],
	out_reqs  => [ "none" ],
	ins       => [ "mem", "ptr", "val" ],
	outs      => [ "M" ],
	mode      => "mode_M",
	emit      => '(%S1) = store %S2',
},

# Floating Point operations

fAdd => {
	template  => $binop,
	irn_flags => [ "rematerializable" ],
	emit      => '%D0 = fadd %S0, %S1',
},

fMul => {
	template => $binop,
	emit     => '%D0 = fmul %S0, %S1',
},

fSub => {
	template  => $binop,
	irn_flags => [ "rematerializable" ],
	emit      => '%D0 = fsub %S0, %S1',
},

fDiv => {
	template => $binop,
	emit     => '%D0 = fdiv %S0, %S1',
},

fMinus => {
	irn_flags => [ "rematerializable" ],
	in_reqs   => [ "gp" ],
	out_reqs  => [ "gp" ],
	emit      => '%D0 = fneg %S0',
	mode      => $mode_gp,
},

fConst => {
	op_flags  => [ "constlike" ],
	irn_flags => [ "rematerializable" ],
	out_reqs  => [ "gp" ],
	emit      => '%D0 = fconst %I',
	mode      => $mode_gp,
},

# Load / Store

fLoad => {
	op_flags  => [ "uses_memory" ],
	irn_flags => [ "rematerializable" ],
	state     => "exc_pinned",
	in_reqs   => [ "none", "gp" ],
	out_reqs  => [ "gp", "none" ],
	ins       => [ "mem", "ptr" ],
	outs      => [ "res", "M" ],
	emit      => '%D0 = fload (%S1)',
},

fStore => {
	op_flags  => [ "uses_memory" ],
	irn_flags => [ "rematerializable" ],
	state     => "exc_pinned",
	in_reqs   => [ "none", "gp", "gp" ],
	out_reqs  => [ "none" ],
	ins       => [ "mem", "ptr", "val" ],
	outs      => [ "M" ],
	mode      => "mode_M",
	emit      => '(%S1) = fstore %S2',
},

);
