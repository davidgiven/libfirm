/*
 * This file is part of libFirm.
 * Copyright (C) 2015 David Given.
 */

/**
 * @file
 * @brief   Function prototypes for the assembler ir node constructors.
 */
#ifndef FIRM_BE_VC4_VC4_NEW_NODES_H
#define FIRM_BE_VC4_VC4_NEW_NODES_H

#include "vc4_nodes_attr.h"

/**
 * Returns the attributes of an vc4 node.
 */
vc4_attr_t *get_vc4_attr(ir_node *node);

const vc4_attr_t *get_vc4_attr_const(const ir_node *node);

/* Include the generated headers */
#include "gen_vc4_new_nodes.h"

#endif
