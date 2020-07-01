/**
 * @file src/cutter-plugin/core_plugin.cpp
 * @brief Main module of the retdec-cutter-plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include "cutter-plugin/core_plugin.h"
#include "r2plugin/core_plugin.h"

void RetDecPlugin::setupPlugin()
{
}

void RetDecPlugin::setupInterface(MainWindow *)
{
}

void RetDecPlugin::registerDecompilers()
{
	Core()->registerDecompiler(new RetDec(Core()));
}

RetDecPlugin::RetDec::RetDec(QObject *parent)
	: Decompiler("r2retdec", "RetDec", parent)
{
}

void RetDecPlugin::RetDec::decompileAt(RVA addr)
{
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock (mutex);

	retdec::r2plugin::R2InfoProvider binInfo(*Core()->core());
	RAnnotatedCode *code = decompile(binInfo, addr);
	if (code == nullptr) {
		code = r_annotated_code_new(strdup("RetDec Decompiler Error: No function at this offset"));
	}

	emit finished(code);
}
