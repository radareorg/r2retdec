/**
 * @file cutter-plugin/R2RetDec.cpp
 * @brief Decompiler wrapper to be used to register with Cutter.
 *
 * This file is based on cutter-plugin/R2GhidraDecompiler.cpp
 * in projcet https://github.com/radareorg/r2ghidra-dec.
 */

#include "R2RetDec.h"
#include "r2plugin/r2retdec.h"
#include <Cutter.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

R2RetDec::R2RetDec(QObject *parent)
	: Decompiler("r2retdec", "RetDec", parent)
{
	task = nullptr;
}

void R2RetDec::decompileAt(RVA addr)
{
	RAnnotatedCode *code = r2retdec_decompile_annotated_code(Core()->core(), addr);
	if(code == nullptr){
		code = r_annotated_code_new(strdup("RetDec Decompiler Error: No function at this offset"));
	}
	emit finished(code);
}
