/*
 * This file is part of libFirm.
 * Copyright (C) 2015 David Given.
 */

/**
 * @file
 * @brief   attributes attached to all vc4 nodes
 */
#ifndef FIRM_BE_VC4_VC4_NODES_ATTR_H
#define FIRM_BE_VC4_VC4_NODES_ATTR_H

#include "bearch.h"

typedef struct vc4_attr_t vc4_attr_t;

struct vc4_attr_t
{
	ir_tarval *value;
	ir_entity *entity;
};

#endif
