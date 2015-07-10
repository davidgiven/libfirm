/*
 * This file is part of libFirm.
 * Copyright (C) 2015 David Given.
 */

/**
 * @file
 * @brief   declaration for the transform function (code selection)
 */
#ifndef FIRM_BE_VC4_VC4_TRANSFORM_H
#define FIRM_BE_VC4_VC4_TRANSFORM_H

#include "firm_types.h"

void vc4_init_transform(void);

void vc4_transform_graph(ir_graph *irg);

#endif
