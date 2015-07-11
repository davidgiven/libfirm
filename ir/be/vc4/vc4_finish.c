/*
 * This file is part of libFirm.
 * Copyright (C) 2014 University of Karlsruhe.
 */

/**
 * @file
 * @brief   vc4 graph touchups before emitting
 * @author  Matthias Braun
 */

#include "vc4_new_nodes.h"
#include "beirg.h"
#include "benode.h"
#include "besched.h"
#include "bespillslots.h"
#include "bestack.h"
#include "be_types.h"
#include "firm_types.h"
#include "gen_vc4_regalloc_if.h"
#include "irgwalk.h"
#include "panic.h"
#include "bearch_vc4_t.h"

static const vc4_attr_t* get_attr_of_frame_referencing_node(const ir_node *node)
{
	if (!is_vc4_Ld(node))
		return NULL;

	const vc4_attr_t *attr = get_vc4_attr_const(node);
	if (!attr->is_frame_entity)
		return NULL;

	return attr;
}

static void vc4_collect_frame_entity_nodes(ir_node *node, void *data)
{
	const vc4_attr_t *attr = get_attr_of_frame_referencing_node(node);
	if (!attr)
		return;

	const ir_entity *entity = attr->entity;
	if (entity != NULL)
		return;
	const ir_type *type = get_type_for_mode(attr->entity_mode);

	be_fec_env_t *env = (be_fec_env_t*)data;
	be_load_needs_frame_entity(env, node, type);
}

static void vc4_set_frame_entity(ir_node *node, ir_entity *entity,
                                 const ir_type *type)
{
	(void)type;
	vc4_attr_t *attr = get_vc4_attr(node);
	attr->entity = entity;
}

static void introduce_epilog(ir_node *ret)
{
	#if 0
	arch_register_t const *const sp_reg = &vc4_registers[REG_SP];
	assert(arch_get_irn_register_req_in(ret, n_vc4_Return_sp) == sp_reg->single_req);

	ir_node  *const sp         = get_irn_n(ret, n_vc4_Return_sp);
	ir_node  *const block      = get_nodes_block(ret);
	ir_graph *const irg        = get_irn_irg(ret);
	ir_type  *const frame_type = get_irg_frame_type(irg);
	unsigned  const frame_size = get_type_size_bytes(frame_type);
	ir_node  *const incsp      = be_new_IncSP(sp_reg, block, sp, -frame_size, 0);
	set_irn_n(ret, n_vc4_Return_sp, incsp);
	sched_add_before(ret, incsp);
	#endif
}

static void introduce_prolog_epilog(ir_graph *irg)
{
	#if 0
	/* introduce epilog for every return node */
	foreach_irn_in(get_irg_end_block(irg), i, ret) {
		assert(is_vc4_Return(ret));
		introduce_epilog(ret);
	}
	#endif

	const arch_register_t *sp_reg     = &vc4_registers[REG_SP];
	ir_node               *start      = get_irg_start(irg);
	ir_node               *block      = get_nodes_block(start);
	ir_node               *initial_sp = be_get_initial_reg_value(irg, sp_reg);
	ir_type               *frame_type = get_irg_frame_type(irg);
	unsigned               frame_size = get_type_size_bytes(frame_type);

	ir_node *const incsp = be_new_IncSP(sp_reg, block, initial_sp, frame_size, 0);
	edges_reroute_except(initial_sp, incsp, incsp);
	sched_add_after(start, incsp);
}

static int get_first_same(const arch_register_req_t* req)
{
	const unsigned other = req->should_be_same;
	for (int i = 0; i < 32; ++i) {
		if (other & (1U << i))
			return i;
	}
	panic("same position not found");
}

static void fix_should_be_same(ir_node *block, void *data)
{
	(void)data;
	sched_foreach(block, node) {
		/* ignore non-vc4 nodes like Copy */
		if (!is_vc4_irn(node))
			continue;

		be_foreach_out(node, i) {
			const arch_register_req_t *req
				= arch_get_irn_register_req_out(node, i);
			if (req->should_be_same == 0)
				continue;

			int same_pos = get_first_same(req);

			const arch_register_t *out_reg = arch_get_irn_register_out(node, i);
			ir_node               *in_node = get_irn_n(node, same_pos);
			const arch_register_t *in_reg  = arch_get_irn_register(in_node);
			if (in_reg == out_reg)
				continue;
			panic("vc4: should_be_same fixup not implemented yet");
		}
	}
}

/**
 * This function is called by the generic backend to correct offsets for
 * nodes accessing the stack.
 */
static void vc4_set_frame_offset(ir_node *irn, int bias)
{
	if (be_is_MemPerm(irn)) {
		be_set_MemPerm_offset(irn, bias);
	#if 0
	} else if (is_vc4_FrameAddr(irn)) {
		vc4_Address_attr_t *attr = get_vc4_Address_attr(irn);
		attr->fp_offset += bias;
	#endif
	} else {
		vc4_attr_t *attr = get_vc4_attr(irn);
		if (attr->is_frame_entity)
			attr->offset += bias;
	}
}

static int vc4_get_sp_bias(const ir_node *node)
{
	(void)node;
	return 0;
}

static ir_entity *vc4_get_frame_entity(const ir_node *irn)
{
	if (be_is_MemPerm(irn))
		return be_get_MemPerm_in_entity(irn, 0);
	if (!is_vc4_irn(irn))
		return NULL;
	const vc4_attr_t *attr = get_vc4_attr_const(irn);
	#if 0
	if (is_vc4_FrameAddr(irn)) {
		const vc4_Address_attr_t *frame_attr = get_vc4_Address_attr_const(irn);
		return frame_attr->entity;
	}
	#endif
	if (attr->is_frame_entity)
		return attr->entity;
	return NULL;
}

void vc4_finish_graph(ir_graph *irg)
{
	be_stack_layout_t *stack_layout = be_get_irg_stack_layout(irg);
	bool               at_begin     = stack_layout->sp_relative;
	be_fec_env_t      *fec_env      = be_new_frame_entity_coalescer(irg);

	irg_walk_graph(irg, NULL, vc4_collect_frame_entity_nodes, fec_env);
	be_assign_entities(fec_env, vc4_set_frame_entity, at_begin);
	be_free_frame_entity_coalescer(fec_env);

	introduce_prolog_epilog(irg);

	/* fix stack entity offsets */
	be_fix_stack_nodes(irg, &vc4_registers[REG_SP]);
	be_birg_from_irg(irg)->non_ssa_regs = NULL;
	be_abi_fix_stack_bias(irg, vc4_get_sp_bias, vc4_set_frame_offset,
	                      vc4_get_frame_entity);

	/* do peephole optimizations and fix stack offsets */
	//vc4_peephole_optimization(irg);

	irg_block_walk_graph(irg, NULL, fix_should_be_same, NULL);
}
