/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   Instrumentation of graphs.
 * @date    14.4.2008
 * @author  Michael Beck
 */
#include <stdbool.h>

#include "error.h"
#include "instrument.h"
#include "ircons.h"
#include "iredges.h"
#include "irgraph_t.h"

void instrument_initcall(ir_graph *irg, ir_entity *ent)
{
	assure_edges(irg);

	/* find the first block */
	ir_node *initial_exec = get_irg_initial_exec(irg);
	ir_node *first_block  = NULL;
	foreach_out_edge(initial_exec, edge) {
		ir_node *succ = get_edge_src_irn(edge);
		if (is_Block(succ)) {
			/* found the first block */
			first_block = succ;
			break;
		}
	}
	if (first_block == NULL) {
		panic("Cannot find first block of irg %+F", irg);
	}

	/* check if this block has only one predecessor */
	int  idx            = -1;
	bool need_new_block = false;
	for (int i = get_Block_n_cfgpreds(first_block); i-- > 0; ) {
		ir_node *p = get_Block_cfgpred(first_block, i);
		if (is_Bad(p))
			continue;
		if (p == initial_exec)
			idx = i;
		else
			need_new_block = true;
	}

	if (need_new_block) {
		ir_node *blk = new_r_Block(irg, 1, &initial_exec);
		set_Block_cfgpred(first_block, idx, new_r_Jmp(blk));
		first_block = blk;
	}

	/* place the call */
	ir_node *const adr         = new_r_Address(irg, ent);
	ir_node *const initial_mem = get_irg_initial_mem(irg);
	ir_node *const call        = new_r_Call(first_block, initial_mem, adr, 0,
	                                        NULL, get_entity_type(ent));
	ir_node *const new_mem     = new_r_Proj(call, mode_M, pn_Call_M);

	edges_reroute_except(initial_mem, new_mem, call);
	/* beware: reroute routes anchor edges also, revert this */
	set_irg_initial_mem(irg, initial_mem);
}
