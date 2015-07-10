/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   calling convention helpers
 * @author  Matthias Braun
 */
#include "vc4_cconv.h"
#include "beirg.h"
#include "irmode.h"
#include "typerep.h"
#include "xmalloc.h"
#include "panic.h"
#include "util.h"

static const unsigned ignore_regs[] = {
	REG_SP,
	REG_DP,
	REG_ESP,
	REG_SR
};

static const arch_register_t* const param_regs[] = {
	&vc4_registers[REG_R0],
	&vc4_registers[REG_R1],
	&vc4_registers[REG_R2],
	&vc4_registers[REG_R3],
	&vc4_registers[REG_R4],
	&vc4_registers[REG_R5],
};

static const arch_register_t* const result_regs[] = {
	&vc4_registers[REG_R0],
	&vc4_registers[REG_R1],
	&vc4_registers[REG_R2],
	&vc4_registers[REG_R3],
};


calling_convention_t *vc4_decide_calling_convention(const ir_graph *irg,
                                                    ir_type *function_type)
{
	/* determine how parameters are passed */
	unsigned            stack_offset = 0;
	size_t const        n_param_regs = ARRAY_SIZE(param_regs);
	size_t const        n_params     = get_method_n_params(function_type);
	size_t              regnum       = 0;
	reg_or_stackslot_t *params       = XMALLOCNZ(reg_or_stackslot_t, n_params);

	for (size_t i = 0; i < n_params; ++i) {
		ir_type            *param_type = get_method_param_type(function_type,i);
		ir_mode            *mode       = get_type_mode(param_type);
		int                 bits       = get_mode_size_bits(mode);
		reg_or_stackslot_t *param      = &params[i];
		param->type = param_type;

		if (regnum < n_param_regs) {
			param->reg0 = param_regs[regnum++];
		} else {
			param->offset = stack_offset;
			/* increase offset 4 bytes so everything is aligned */
			stack_offset += MAX(bits / 8, 4);
			continue;
		}

		/* we might need a 2nd 32bit component (for 64bit or double values) */
		if (bits > 32) {
			if (bits > 64)
				panic("only 32 and 64bit modes supported");

			if (regnum < n_param_regs) {
				const arch_register_t *reg = param_regs[regnum++];
				param->reg1 = reg;
			} else {
				ir_mode *pmode = param_regs[0]->cls->mode;
				ir_type *type  = get_type_for_mode(pmode);
				param->type    = type;
				param->offset  = stack_offset;
				assert(get_mode_size_bits(pmode) == 32);
				stack_offset += 4;
			}
		}
	}
	unsigned const n_param_regs_used = regnum;

	size_t const        n_result_regs= ARRAY_SIZE(result_regs);
	size_t              n_results    = get_method_n_ress(function_type);
	reg_or_stackslot_t *results      = XMALLOCNZ(reg_or_stackslot_t, n_results);
	regnum = 0;
	for (size_t i = 0; i < n_results; ++i) {
		ir_type            *result_type = get_method_res_type(function_type, i);
		ir_mode            *result_mode = get_type_mode(result_type);
		reg_or_stackslot_t *result      = &results[i];

		if (get_mode_size_bits(result_mode) > 32) {
			panic("results with more than 32bits not supported yet");
		}

		if (regnum >= n_result_regs) {
			panic("too many results");
		} else {
			const arch_register_t *reg = result_regs[regnum++];
			result->reg0 = reg;
		}
	}

	calling_convention_t *cconv = XMALLOCZ(calling_convention_t);
	cconv->parameters       = params;
	cconv->param_stack_size = stack_offset;
	cconv->n_param_regs     = n_param_regs_used;
	cconv->results          = results;

	/* setup allocatable registers */
	if (irg != NULL) {
		be_irg_t       *birg      = be_birg_from_irg(irg);
		size_t          n_ignores = ARRAY_SIZE(ignore_regs);
		struct obstack *obst      = &birg->obst;

		assert(birg->allocatable_regs == NULL);
		birg->allocatable_regs = rbitset_obstack_alloc(obst, N_VC4_REGISTERS);
		rbitset_set_all(birg->allocatable_regs, N_VC4_REGISTERS);
		for (size_t r = 0; r < n_ignores; ++r) {
			rbitset_clear(birg->allocatable_regs, ignore_regs[r]);
		}
	}

	return cconv;
}

void vc4_free_calling_convention(calling_convention_t *cconv)
{
	free(cconv->parameters);
	free(cconv->results);
	free(cconv);
}
