/*
 * This file is part of libFirm.
 * Copyright (C) 2015 David Given.
 */

/**
 * @file
 * @brief   code selection (transform FIRM into vc4 FIRM)
 */
#include "irnode_t.h"
#include "irgraph_t.h"
#include "irmode_t.h"
#include "irgmod.h"
#include "iredges.h"
#include "ircons.h"
#include "iropt_t.h"
#include "debug.h"
#include "panic.h"
#include "util.h"

#include "benode.h"
#include "betranshlp.h"
#include "beirg.h"

#include "bearch_vc4_t.h"
#include "vc4_nodes_attr.h"
#include "vc4_transform.h"
#include "vc4_new_nodes.h"
#include "vc4_cconv.h"

#include "gen_vc4_regalloc_if.h"

DEBUG_ONLY(static firm_dbg_module_t *dbg = NULL;)

#define VC4_PO2_STACK_ALIGNMENT 2

typedef ir_node* (*new_binop_func)(dbg_info *dbgi, ir_node *block,
                                   ir_node *left, ir_node *right);

static const arch_register_t *sp_reg = &vc4_registers[REG_SP];
static ir_mode *gp_regs_mode;
static be_stackorder_t       *stackorder;
static calling_convention_t  *cconv = NULL;
static pmap                  *node_to_stack;
static be_start_info_t        start_mem;
static be_start_info_t        start_val[N_VC4_REGISTERS];
static unsigned               start_callee_saves_offset;

static const arch_register_t *const callee_saves[] = {
	&vc4_registers[REG_R6],
	&vc4_registers[REG_R7],
	&vc4_registers[REG_R8],
	&vc4_registers[REG_R9],
	&vc4_registers[REG_R10],
	&vc4_registers[REG_R11],
	&vc4_registers[REG_R12],
	&vc4_registers[REG_R14],
	&vc4_registers[REG_R15],
	&vc4_registers[REG_R16],
	&vc4_registers[REG_R17],
	&vc4_registers[REG_R18],
	&vc4_registers[REG_R19],
	&vc4_registers[REG_R20],
	&vc4_registers[REG_R21],
	&vc4_registers[REG_R22],
	&vc4_registers[REG_R23],
	&vc4_registers[REG_LR],
};

static const arch_register_t *const caller_saves[] = {
	&vc4_registers[REG_R0],
	&vc4_registers[REG_R1],
	&vc4_registers[REG_R2],
	&vc4_registers[REG_R3],
	&vc4_registers[REG_R4],
	&vc4_registers[REG_R5],
	&vc4_registers[REG_LR],
};

/**
 * returns true if mode should be stored in a general purpose register
 */
static inline bool mode_needs_gp_reg(ir_mode *mode)
{
	return get_mode_arithmetic(mode) == irma_twos_complement;
}

static ir_node *transform_binop(ir_node *node, new_binop_func new_func)
{
	ir_node  *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi      = get_irn_dbg_info(node);
	ir_node  *left      = get_binop_left(node);
	ir_node  *new_left  = be_transform_node(left);
	ir_node  *right     = get_binop_right(node);
	ir_node  *new_right = be_transform_node(right);

	return new_func(dbgi, new_block, new_left, new_right);
}

static ir_node *gen_And(ir_node *node)
{
	return transform_binop(node, new_bd_vc4_And);
}

static ir_node *gen_Or(ir_node *node)
{
	return transform_binop(node, new_bd_vc4_Or);
}

static ir_node *gen_Eor(ir_node *node)
{
	return transform_binop(node, new_bd_vc4_Xor);
}

static ir_node *gen_Div(ir_node *node)
{
#ifndef NDEBUG
	ir_mode *mode = get_Div_resmode(node);
	assert(mode_is_float(mode));
#endif
	return transform_binop(node, new_bd_vc4_fDiv);
}

static ir_node *gen_Shl(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);
	if (get_mode_modulo_shift(mode) != 32)
		panic("modulo shift!=32 not supported");
	return transform_binop(node, new_bd_vc4_Shl);
}

static ir_node *gen_Shr(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);
	if (get_mode_modulo_shift(mode) != 32)
		panic("modulo shift!=32 not supported");
	return transform_binop(node, new_bd_vc4_Shr);
}

static ir_node *gen_Add(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);

	if (mode_is_float(mode)) {
		return transform_binop(node, new_bd_vc4_fAdd);
	}
	return transform_binop(node, new_bd_vc4_Add);
}

static ir_node *gen_Sub(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);

	if (mode_is_float(mode)) {
		return transform_binop(node, new_bd_vc4_fSub);
	}
	return transform_binop(node, new_bd_vc4_Sub);
}

static ir_node *gen_Mul(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);

	if (mode_is_float(mode)) {
		return transform_binop(node, new_bd_vc4_fMul);
	}
	return transform_binop(node, new_bd_vc4_Mul);
}


typedef ir_node* (*new_unop_func)(dbg_info *dbgi, ir_node *block, ir_node *op);

static ir_node *transform_unop(ir_node *node, int op_index, new_unop_func new_func)
{
	ir_node  *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi      = get_irn_dbg_info(node);
	ir_node  *op        = get_irn_n(node, op_index);
	ir_node  *new_op    = be_transform_node(op);

	return new_func(dbgi, new_block, new_op);
}

static ir_node *gen_Minus(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);

	if (mode_is_float(mode)) {
		return transform_unop(node, n_Minus_op, new_bd_vc4_fMinus);
	}
	return transform_unop(node, n_Minus_op, new_bd_vc4_Minus);
}

static ir_node *gen_Not(ir_node *node)
{
	return transform_unop(node, n_Not_op, new_bd_vc4_Not);
}

static ir_node *gen_Const(ir_node *node)
{
	ir_node   *new_block = be_transform_nodes_block(node);
	dbg_info  *dbgi      = get_irn_dbg_info(node);
	ir_tarval *value     = get_Const_tarval(node);
	return new_bd_vc4_Const(dbgi, new_block, value);
}

static ir_node *gen_Address(ir_node *node)
{
	ir_node   *new_block = be_transform_nodes_block(node);
	dbg_info  *dbgi      = get_irn_dbg_info(node);
	ir_entity *entity    = get_Address_entity(node);
	return new_bd_vc4_Address(dbgi, new_block, entity);
}

static ir_node *gen_Load(ir_node *node)
{
	ir_node  *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi      = get_irn_dbg_info(node);
	ir_node  *ptr       = get_Load_ptr(node);
	ir_node  *new_ptr   = be_transform_node(ptr);
	ir_node  *mem       = get_Load_mem(node);
	ir_node  *new_mem   = be_transform_node(mem);
	ir_mode  *mode      = get_Load_mode(node);

	if (mode_is_float(mode)) {
		return new_bd_vc4_fLoad(dbgi, new_block, new_mem, new_ptr);
	}
	return new_bd_vc4_Load(dbgi, new_block, new_mem, new_ptr);
}

static ir_node *gen_Store(ir_node *node)
{
	ir_node  *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi      = get_irn_dbg_info(node);
	ir_node  *ptr       = get_Store_ptr(node);
	ir_node  *new_ptr   = be_transform_node(ptr);
	ir_node  *val       = get_Store_value(node);
	ir_node  *new_val   = be_transform_node(val);
	ir_node  *mem       = get_Store_mem(node);
	ir_node  *new_mem   = be_transform_node(mem);
	ir_mode  *mode      = get_irn_mode(node);

	if (mode_is_float(mode)) {
		return new_bd_vc4_fStore(dbgi, new_block, new_mem, new_ptr, new_val);
	}
	return new_bd_vc4_Store(dbgi, new_block, new_mem, new_ptr, new_val);
}

static ir_node *gen_Jmp(ir_node *node)
{
	ir_node  *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi      = get_irn_dbg_info(node);
	return new_bd_vc4_Jmp(dbgi, new_block);
}

/**
 * Produces the type which sits between the stack args and the locals on the
 * stack. It will contain the return address and space to store the old base
 * pointer.
 * @return The Firm type modeling the ABI between type.
 */
static ir_type *vc4_get_between_type(void)
{
	static ir_type *between_type = NULL;
	if (between_type == NULL) {
		between_type = new_type_class(new_id_from_str("vc4_between_type"));
		set_type_size_bytes(between_type, 0);
	}

	return between_type;
}

static void create_stacklayout(ir_graph *irg)
{
	ir_entity         *entity        = get_irg_entity(irg);
	ir_type           *function_type = get_entity_type(entity);
	be_stack_layout_t *layout        = be_get_irg_stack_layout(irg);

	/* calling conventions must be decided by now */
	assert(cconv != NULL);

	/* construct argument type */
	ident   *const arg_type_id = new_id_fmt("%s_arg_type", get_entity_ident(entity));
	ir_type *const arg_type    = new_type_struct(arg_type_id);
	for (unsigned p = 0, n_params = get_method_n_params(function_type);
	     p < n_params; ++p) {
		reg_or_stackslot_t *param = &cconv->parameters[p];
		if (param->type == NULL)
			continue;

		ident *const id = new_id_fmt("param_%u", p);
		param->entity = new_entity(arg_type, id, param->type);
		set_entity_offset(param->entity, param->offset);
	}

	/* TODO: what about external functions? we don't know most of the stack
	 * layout for them. And probably don't need all of this... */
	memset(layout, 0, sizeof(*layout));
	layout->frame_type     = get_irg_frame_type(irg);
	layout->between_type   = vc4_get_between_type();
	layout->arg_type       = arg_type;
	layout->initial_offset = 0;
	layout->initial_bias   = 0;
	layout->sp_relative    = true;

	assert(N_FRAME_TYPES == 3);
	layout->order[0] = layout->frame_type;
	layout->order[1] = layout->between_type;
	layout->order[2] = layout->arg_type;
}

static ir_node *gen_Start(ir_node *node)
{
	ir_graph       *irg           = get_irn_irg(node);
	ir_entity      *entity        = get_irg_entity(irg);
	ir_type        *function_type = get_entity_type(entity);
	ir_node        *new_block     = be_transform_nodes_block(node);
	dbg_info       *dbgi          = get_irn_dbg_info(node);

	unsigned n_outs = 2; /* memory, sp */
	n_outs += cconv->n_param_regs;
	n_outs += ARRAY_SIZE(callee_saves);
	ir_node *start = new_bd_vc4_Start(dbgi, new_block, n_outs);
	unsigned o     = 0;

	be_make_start_mem(&start_mem, start, o++);

	be_make_start_out(&start_val[REG_SP], start, o++, &vc4_registers[REG_SP], true);

	/* function parameters in registers */
	for (size_t i = 0; i < get_method_n_params(function_type); ++i) {
		const reg_or_stackslot_t *param = &cconv->parameters[i];
		const arch_register_t    *reg0  = param->reg0;
		if (reg0)
			be_make_start_out(&start_val[reg0->global_index], start, o++, reg0, false);
		const arch_register_t *reg1 = param->reg1;
		if (reg1)
			be_make_start_out(&start_val[reg1->global_index], start, o++, reg1, false);
	}
	/* callee save regs */
	start_callee_saves_offset = o;
	for (size_t i = 0; i < ARRAY_SIZE(callee_saves); ++i) {
		const arch_register_t *reg = callee_saves[i];
		arch_set_irn_register_req_out(start, o, reg->single_req);
		arch_set_irn_register_out(start, o, reg);
		++o;
	}
	assert(n_outs == o);

	return start;
}

static ir_node *get_stack_pointer_for(ir_node *node)
{
	/* get predecessor in stack_order list */
	ir_node *stack_pred = be_get_stack_pred(stackorder, node);
	if (stack_pred == NULL) {
		/* first stack user in the current block. We can simply use the
		 * initial sp_proj for it */
		ir_graph *irg = get_irn_irg(node);
		return be_get_start_proj(irg, &start_val[REG_SP]);
	}

	be_transform_node(stack_pred);
	ir_node *stack = pmap_get(ir_node, node_to_stack, stack_pred);
	if (stack == NULL) {
		return get_stack_pointer_for(stack_pred);
	}

	return stack;
}

static ir_node *gen_Return(ir_node *node)
{
	int                               p     = n_vc4_Return_first_result;
	unsigned                    const n_res = get_Return_n_ress(node);
	unsigned                    const n_ins = p + n_res;
	ir_node                   **const in    = ALLOCAN(ir_node*, n_ins);
	ir_graph                   *const irg   = get_irn_irg(node);
	arch_register_req_t const **const reqs  = be_allocate_in_reqs(irg, n_ins);

	in[n_vc4_Return_mem]   = be_transform_node(get_Return_mem(node));
	reqs[n_vc4_Return_mem] = arch_no_register_req;

	in[n_vc4_Return_stack]   = get_irg_frame(irg);
	reqs[n_vc4_Return_stack] = vc4_registers[REG_SP].single_req;

	for (unsigned i = 0; i != n_res; ++p, ++i) {
		ir_node *const res = get_Return_res(node, i);
		in[p]   = be_transform_node(res);
		reqs[p] = arch_get_irn_register_req(in[p])->cls->class_req;
	}

	dbg_info *const dbgi  = get_irn_dbg_info(node);
	ir_node  *const block = be_transform_nodes_block(node);
	ir_node  *const ret   = new_bd_vc4_Return(dbgi, block, n_ins, in);
	arch_set_irn_register_reqs_in(ret, reqs);

	return ret;
}

static ir_node *gen_Call(ir_node *node)
{
	ir_graph             *irg          = get_irn_irg(node);
	ir_node              *callee       = get_Call_ptr(node);
	ir_node              *new_block    = be_transform_nodes_block(node);
	ir_node              *mem          = get_Call_mem(node);
	ir_node              *new_mem      = be_transform_node(mem);
	dbg_info             *dbgi         = get_irn_dbg_info(node);
	ir_type              *type         = get_Call_type(node);
	calling_convention_t *cconv        = vc4_decide_calling_convention(NULL, type);
	size_t                n_params     = get_Call_n_params(node);
	size_t const          n_param_regs = cconv->n_param_regs;
	/* max inputs: memory, stack, callee, register arguments */
	size_t const          max_inputs   = 3 + n_param_regs;
	ir_node             **in           = ALLOCAN(ir_node*, max_inputs);
	ir_node             **sync_ins     = ALLOCAN(ir_node*, n_params);
	arch_register_req_t const **const in_req = be_allocate_in_reqs(irg, max_inputs);
	size_t                in_arity       = 0;
	size_t                sync_arity     = 0;
	size_t const          n_caller_saves = ARRAY_SIZE(caller_saves);
	ir_entity            *entity         = NULL;

	assert(n_params == get_method_n_params(type));

	/* memory input */
	int mem_pos     = in_arity++;
	in_req[mem_pos] = arch_no_register_req;
	/* stack pointer (create parameter stackframe + align stack)
	 * Note that we always need an IncSP to ensure stack alignment */
	ir_node *new_frame = get_stack_pointer_for(node);
	ir_node *incsp     = be_new_IncSP(sp_reg, new_block, new_frame,
	                                  cconv->param_stack_size,
	                                  VC4_PO2_STACK_ALIGNMENT);
	int sp_pos = in_arity++;
	in_req[sp_pos] = sp_reg->single_req;
	in[sp_pos]     = incsp;

	/* parameters */
	for (size_t p = 0; p < n_params; ++p) {
		ir_node                  *value      = get_Call_param(node, p);
		ir_node                  *new_value  = be_transform_node(value);
		ir_node                  *new_value1 = NULL;
		const reg_or_stackslot_t *param      = &cconv->parameters[p];
		ir_type                  *param_type = get_method_param_type(type, p);
		ir_mode                  *mode       = get_type_mode(param_type);

		/* put value into registers */
		if (param->reg0 != NULL) {
			in[in_arity]     = new_value;
			in_req[in_arity] = param->reg0->single_req;
			++in_arity;
			if (new_value1 == NULL)
				continue;
		}
		if (param->reg1 != NULL) {
			assert(new_value1 != NULL);
			in[in_arity]     = new_value1;
			in_req[in_arity] = param->reg1->single_req;
			++in_arity;
			continue;
		}

		/* we need a store if we're here */
		if (new_value1 != NULL) {
			new_value = new_value1;
			mode      = mode_Iu;
		}

		/* create a parameter frame if necessary */
		ir_node *str;
		str = new_bd_vc4_St(dbgi, new_block, incsp, new_value, new_mem);
		vc4_attr_t *attrs = get_vc4_attr(str);
		attrs->is_frame_entity = false;
		attrs->constant = param->offset;
		sync_ins[sync_arity++] = str;
	}

	/* construct memory input */
	if (sync_arity == 0) {
		in[mem_pos] = new_mem;
	} else if (sync_arity == 1) {
		in[mem_pos] = sync_ins[0];
	} else {
		in[mem_pos] = new_r_Sync(new_block, sync_arity, sync_ins);
	}

	/* Count outputs. */
	unsigned const out_arity = pn_vc4_Bl_first_result + n_caller_saves;

	/* Call via register. Add the register to the set of inputs and tell
	 * the node which one it is. */
	unsigned target_register = in_arity;

	in[in_arity]     = be_transform_node(callee);
	in_req[in_arity] = vc4_reg_classes[CLASS_vc4_gp].class_req;
	++in_arity;

	ir_node *res = new_bd_vc4_Bl(dbgi, new_block, in_arity, in, out_arity);
	vc4_attr_t *attrs = get_vc4_attr(res);
	attrs->which_register = target_register;

	arch_set_irn_register_reqs_in(res, in_req);

	/* create output register reqs */
	arch_set_irn_register_req_out(res, pn_vc4_Bl_M, arch_no_register_req);
	arch_copy_irn_out_info(res, pn_vc4_Bl_stack, incsp);

	for (size_t o = 0; o < n_caller_saves; ++o) {
		const arch_register_t *reg = caller_saves[o];
		arch_set_irn_register_req_out(res, pn_vc4_Bl_first_result + o, reg->single_req);
	}

	/* copy pinned attribute */
	set_irn_pinned(res, get_irn_pinned(node));

	/* IncSP to destroy the call stackframe */
	ir_node *const call_stack = new_r_Proj(res, vc4_mode_gp, pn_vc4_Bl_stack);
	incsp = be_new_IncSP(sp_reg, new_block, call_stack, -cconv->param_stack_size, 0);
	/* if we are the last IncSP producer in a block then we have to keep
	 * the stack value.
	 * Note: This here keeps all producers which is more than necessary */
	keep_alive(incsp);

	pmap_insert(node_to_stack, node, incsp);

	vc4_free_calling_convention(cconv);
	return res;
}

static ir_node *gen_Phi(ir_node *node)
{
	ir_mode                   *mode = get_irn_mode(node);
	const arch_register_req_t *req;
	if (mode_needs_gp_reg(mode)) {
		req  = vc4_reg_classes[CLASS_vc4_gp].class_req;
	} else {
		req = arch_no_register_req;
	}

	return be_transform_phi(node, req);
}

static ir_node *gen_Proj_Proj_Start(ir_node *node)
{
	/* Proj->Proj->Start must be a method argument */
	assert(get_Proj_num(get_Proj_pred(node)) == pn_Start_T_args);

	ir_node                  *const new_block = be_transform_nodes_block(node);
	ir_graph                 *const irg       = get_irn_irg(new_block);
	unsigned                  const pn        = get_Proj_num(node);
	reg_or_stackslot_t const *const param     = &cconv->parameters[pn];
	if (param->reg0 != NULL) {
		/* argument transmitted in register */
		return be_get_start_proj(irg, &start_val[param->reg0->global_index]);
	} else {
		/* argument transmitted on stack */
		ir_node *const fp   = get_irg_frame(irg);
		ir_node *const mem  = be_get_start_proj(irg, &start_mem);
		ir_mode *const mode = get_type_mode(param->type);

		ir_node *load;
		ir_node *value;

		/* Offset isn't set here; it'll get fixed up at the last stage once
		 * we know how big the stack frame is. */
		load  = new_bd_vc4_Ld(NULL, new_block, fp, mem);
		vc4_attr_t *attrs = get_vc4_attr(load);
		attrs->is_frame_entity = true;
		attrs->entity_mode = mode;
		attrs->entity = param->entity;

		value = new_r_Proj(load, vc4_mode_gp, pn_vc4_Ld_res);

		set_irn_pinned(load, op_pin_state_floats);

		return value;
	}
}

/**
 * Finds number of output value of a mode_T node which is constrained to
 * a single specific register.
 */
static int find_out_for_reg(ir_node *node, const arch_register_t *reg)
{
	be_foreach_out(node, o) {
		const arch_register_req_t *req = arch_get_irn_register_req_out(node, o);
		if (req == reg->single_req)
			return o;
	}
	return -1;
}

static ir_node *gen_Proj_Proj_Call(ir_node *node)
{
	unsigned              pn            = get_Proj_num(node);
	ir_node              *call          = get_Proj_pred(get_Proj_pred(node));
	ir_node              *new_call      = be_transform_node(call);
	ir_type              *function_type = get_Call_type(call);
	calling_convention_t *cconv
		= vc4_decide_calling_convention(NULL, function_type);
	const reg_or_stackslot_t *res = &cconv->results[pn];

	assert(res->reg0 != NULL && res->reg1 == NULL);
	int regn = find_out_for_reg(new_call, res->reg0);
	if (regn < 0) {
		panic("Internal error in calling convention for return %+F", node);
	}
	ir_mode *const mode = res->reg0->cls->mode;

	vc4_free_calling_convention(cconv);

	return new_r_Proj(new_call, mode, regn);
}

static ir_node *gen_Proj_Call(ir_node *node)
{
	unsigned pn        = get_Proj_num(node);
	ir_node *call      = get_Proj_pred(node);
	ir_node *new_call  = be_transform_node(call);
	switch ((pn_Call)pn) {
	case pn_Call_M:
		return new_r_Proj(new_call, mode_M, pn_vc4_Bl_M);
	case pn_Call_X_regular:
	case pn_Call_X_except:
	case pn_Call_T_result:
		break;
	}
	panic("unexpected Call proj %u", pn);
}

static ir_node *gen_Proj_Proj(ir_node *node)
{
	ir_node *pred      = get_Proj_pred(node);
	ir_node *pred_pred = get_Proj_pred(pred);
	if (is_Call(pred_pred)) {
		return gen_Proj_Proj_Call(node);
	} else if (is_Start(pred_pred)) {
		return gen_Proj_Proj_Start(node);
	}
	panic("code selection didn't expect Proj(Proj) after %+F", pred_pred);
}

static ir_node *gen_Proj_Load(ir_node *node)
{
	ir_node *load     = get_Proj_pred(node);
	ir_node *new_load = be_transform_node(load);
	switch ((pn_Load)get_Proj_num(node)) {
	case pn_Load_M:
		return new_r_Proj(new_load, mode_M, pn_vc4_Load_M);
	case pn_Load_res:
		return new_r_Proj(new_load, gp_regs_mode, pn_vc4_Load_res);
	case pn_Load_X_regular:
	case pn_Load_X_except:
		panic("exception handling not supported yet");
	}
	panic("invalid Proj %+F -> %+F", node, load);
}

static ir_node *gen_Proj_Store(ir_node *node)
{
	ir_node *store     = get_Proj_pred(node);
	ir_node *new_store = be_transform_node(store);
	switch ((pn_Store)get_Proj_num(node)) {
	case pn_Store_M:
		return new_store;
	case pn_Store_X_regular:
	case pn_Store_X_except:
		panic("exception handling not supported yet");
	}
	panic("invalid Proj %+F -> %+F", node, store);
}

static ir_node *gen_Proj_Start(ir_node *node)
{
	dbg_info *dbgi      = get_irn_dbg_info(node);
	ir_node  *start     = get_Proj_pred(node);
	ir_node  *new_start = be_transform_node(start);
	unsigned  pn        = get_Proj_num(node);

	switch ((pn_Start)pn) {
	case pn_Start_M:
		return be_get_start_proj(get_irn_irg(node), &start_mem);
	case pn_Start_T_args:
		return new_r_Bad(get_irn_irg(node), mode_T);
	case pn_Start_P_frame_base:
		return be_get_start_proj(get_irn_irg(node), &start_val[REG_SP]);
	}
	panic("unexpected Start proj %u", pn);
}

static void vc4_register_transformers(void)
{
	be_start_transform_setup();

	be_set_transform_function(op_Add,     gen_Add);
	be_set_transform_function(op_Address, gen_Address);
	be_set_transform_function(op_And,     gen_And);
	be_set_transform_function(op_Call,    gen_Call);
	be_set_transform_function(op_Const,   gen_Const);
	be_set_transform_function(op_Div,     gen_Div);
	be_set_transform_function(op_Eor,     gen_Eor);
	be_set_transform_function(op_Jmp,     gen_Jmp);
	be_set_transform_function(op_Load,    gen_Load);
	be_set_transform_function(op_Minus,   gen_Minus);
	be_set_transform_function(op_Mul,     gen_Mul);
	be_set_transform_function(op_Not,     gen_Not);
	be_set_transform_function(op_Or,      gen_Or);
	be_set_transform_function(op_Phi,     gen_Phi);
	be_set_transform_function(op_Return,  gen_Return);
	be_set_transform_function(op_Shl,     gen_Shl);
	be_set_transform_function(op_Shr,     gen_Shr);
	be_set_transform_function(op_Start,   gen_Start);
	be_set_transform_function(op_Store,   gen_Store);
	be_set_transform_function(op_Sub,     gen_Sub);

	be_set_transform_proj_function(op_Call,  gen_Proj_Call);
	be_set_transform_proj_function(op_Load,  gen_Proj_Load);
	be_set_transform_proj_function(op_Proj,  gen_Proj_Proj);
	be_set_transform_proj_function(op_Start, gen_Proj_Start);
	be_set_transform_proj_function(op_Store, gen_Proj_Store);
}

static const unsigned ignore_regs[] = {
	REG_SP,
	REG_DP,
	REG_ESP,
	REG_SR
};

static void setup_calling_convention(ir_graph *irg)
{
	be_irg_t       *birg = be_birg_from_irg(irg);
	struct obstack *obst = &birg->obst;

	unsigned *allocatable_regs = rbitset_obstack_alloc(obst, N_VC4_REGISTERS);
	rbitset_set_all(allocatable_regs, N_VC4_REGISTERS);
	for (size_t r = 0, n = ARRAY_SIZE(ignore_regs); r < n; ++r) {
		rbitset_clear(allocatable_regs, ignore_regs[r]);
	}
	birg->allocatable_regs = allocatable_regs;
}

/**
 * Transform generic IR-nodes into vc4 machine instructions
 */
void vc4_transform_graph(ir_graph *irg)
{
	assure_irg_properties(irg, IR_GRAPH_PROPERTY_NO_TUPLES
	                         | IR_GRAPH_PROPERTY_NO_BADS);

	gp_regs_mode = vc4_reg_classes[CLASS_vc4_gp].mode;

	vc4_register_transformers();

	node_to_stack = pmap_create();

	assert(cconv == NULL);
	stackorder = be_collect_stacknodes(irg);
	ir_entity *entity = get_irg_entity(irg);
	cconv = vc4_decide_calling_convention(irg, get_entity_type(entity));
	create_stacklayout(irg);
	be_add_parameter_entity_stores(irg);

	be_transform_graph(irg, NULL);

	be_free_stackorder(stackorder);
	stackorder = NULL;

	vc4_free_calling_convention(cconv);
	cconv = NULL;

	ir_type *frame_type = get_irg_frame_type(irg);
	if (get_type_state(frame_type) == layout_undefined) {
		default_layout_compound_type(frame_type);
	}

	pmap_destroy(node_to_stack);
	node_to_stack = NULL;
}

void vc4_init_transform(void)
{
	FIRM_DBG_REGISTER(dbg, "firm.be.vc4.transform");
}
