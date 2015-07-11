/*
 * This file is part of libFirm.
 * Copyright (C) 2015 David Given.
 */

/**
 * @file
 * @brief    The main vc4 backend driver file.
 */
#include "vc4_emitter.h"
#include "vc4_new_nodes.h"
#include "vc4_transform.h"
#include "be_t.h"
#include "beirg.h"
#include "bemodule.h"
#include "benode.h"
#include "bera.h"
#include "bestack.h"
#include "gen_vc4_regalloc_if.h"
#include "irprog_t.h"
#include "lower_builtins.h"
#include "lower_calls.h"
#include "panic.h"
#include "bearch_vc4_t.h"

DEBUG_ONLY(static firm_dbg_module_t *dbg = NULL;)

#define VC4_MACHINE_SIZE 32

ir_mode *vc4_mode_gp;

/**
 * Transforms the standard firm graph into a VC4 firm graph
 */
static void vc4_select_instructions(ir_graph *irg)
{
	/* transform nodes into assembler instructions */
	be_timer_push(T_CODEGEN);
	vc4_transform_graph(irg);
	be_timer_pop(T_CODEGEN);
	be_dump(DUMP_BE, irg, "code-selection");
}

static ir_node *vc4_new_spill(ir_node *value, ir_node *after)
{
	(void)value;
	(void)after;
	panic("spilling not implemented yet");
}

static ir_node *vc4_new_reload(ir_node *value, ir_node *spill,
                                    ir_node *before)
{
	(void)value;
	(void)spill;
	(void)before;
	panic("reload not implemented yet");
}

static const regalloc_if_t vc4_regalloc_if = {
	.spill_cost  = 7,
	.reload_cost = 5,
	.new_spill   = vc4_new_spill,
	.new_reload  = vc4_new_reload,
};

static void vc4_generate_code(FILE *output, const char *cup_name)
{
	be_begin(output, cup_name);
	unsigned *const sp_is_non_ssa = rbitset_malloc(N_VC4_REGISTERS);
	rbitset_set(sp_is_non_ssa, REG_SP);

	foreach_irp_irg(i, irg) {
		if (!be_step_first(irg))
			continue;

		be_birg_from_irg(irg)->non_ssa_regs = sp_is_non_ssa;
		vc4_select_instructions(irg);

		be_step_schedule(irg);

		be_step_regalloc(irg, &vc4_regalloc_if);

		be_fix_stack_nodes(irg, &vc4_registers[REG_SP]);
		be_birg_from_irg(irg)->non_ssa_regs = NULL;

		vc4_finish_graph(irg);
		vc4_emit_function(irg);

		be_step_last(irg);
	}

	be_finish();
}

static void vc4_init(void)
{
	vc4_mode_gp    = new_int_mode("vc4_gp", irma_twos_complement,
	                              VC4_MACHINE_SIZE, 0, VC4_MACHINE_SIZE);

	vc4_register_init();
	vc4_create_opcodes();
}

static void vc4_finish(void)
{
	vc4_free_opcodes();
}

static void vc4_lower_for_target(void)
{
	lower_builtins(0, NULL);
	be_after_irp_transform("lower-builtins");

	/* lower compound param handling */
	lower_calls_with_compounds(LF_RETURN_HIDDEN);
	be_after_irp_transform("lower-calls");
}

static int vc4_is_mux_allowed(ir_node *sel, ir_node *mux_false,
                                   ir_node *mux_true)
{
	(void)sel;
	(void)mux_false;
	(void)mux_true;
	return false;
}

/**
 * Returns the libFirm configuration parameter for this backend.
 */
static const backend_params *vc4_get_backend_params(void)
{
	static backend_params p = {
		.byte_order_big_endian         = false,
		.pic_supported                 = false,
		.unaligned_memaccess_supported = false,
		.modulo_shift                  = 32,
		.dep_param                     = NULL,
		.allow_ifconv                  = vc4_is_mux_allowed,
		.machine_size                  = 32,
		.mode_float_arithmetic         = NULL,
		.type_long_long                = NULL,
		.type_unsigned_long_long       = NULL,
		.type_long_double              = NULL,
		.stack_param_align             = 4,
		.float_int_overflow            = ir_overflow_min_max,
	};
	return &p;
}

static int vc4_is_valid_clobber(const char *clobber)
{
	(void)clobber;
	return false;
}

static unsigned vc4_get_op_estimated_cost(const ir_node *node)
{
	if (is_vc4_Load(node))
		return 5;
	if (is_vc4_Store(node))
		return 7;
	return 1;
}

static arch_isa_if_t const vc4_isa_if = {
	.n_registers           = N_VC4_REGISTERS,
	.registers             = vc4_registers,
	.n_register_classes    = N_VC4_CLASSES,
	.register_classes      = vc4_reg_classes,
	.init                  = vc4_init,
	.finish                = vc4_finish,
	.get_params            = vc4_get_backend_params,
	.generate_code         = vc4_generate_code,
	.lower_for_target      = vc4_lower_for_target,
	.is_valid_clobber      = vc4_is_valid_clobber,
	.get_op_estimated_cost = vc4_get_op_estimated_cost,
};

BE_REGISTER_MODULE_CONSTRUCTOR(be_init_arch_vc4)
void be_init_arch_vc4(void)
{
	be_register_isa_if("vc4", &vc4_isa_if);
	FIRM_DBG_REGISTER(dbg, "firm.be.vc4.cg");
	vc4_init_transform();
}
