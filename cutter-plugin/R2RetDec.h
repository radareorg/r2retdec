/**
 * @file cutter-plugin/R2RetDec.h
 * @brief Decompiler wrapper to be used to register with Cutter.
 *
 * This file is based on cutter-plugin/R2GhidraDecompiler.cpp
 * in projcet https://github.com/radareorg/r2ghidra-dec.
 */

#ifndef RETDEC_R2PLUGIN_R2RETDEC_H
#define RETDEC_R2PLUGIN_R2RETDEC_H

#include "Decompiler.h"
#include "R2Task.h"

class R2RetDec: public Decompiler
{
	private:
		R2Task *task;

	public:
		R2RetDec(QObject *parent = nullptr);
		void decompileAt(RVA addr) override;
		bool isRunning() override { return task != nullptr; }
};

#endif //RETDEC_R2PLUGIN_R2RETDEC_H
