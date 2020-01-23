/**
 * @file cutter-plugin/R2RetDecPlugin.cpp
 * @brief Cutter plugin definition. Registers RetDec decompiler.
 *
 * This file is based on cutter-plugin/R2GhidraPlugin.cpp
 * in projcet https://github.com/radareorg/r2ghidra-dec.
 */

#include "R2RetDec.h"
#include "R2RetDecPlugin.h"

void R2RetDecPlugin::setupPlugin()
{
}

void R2RetDecPlugin::setupInterface(MainWindow *)
{
}

void R2RetDecPlugin::registerDecompilers()
{
	Core()->registerDecompiler(new R2RetDec(Core()));
}
