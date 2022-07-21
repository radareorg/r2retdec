/**
 * @file src/iaito-plugin/core_plugin.cpp
 * @brief Main module of the retdec-iaito-plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <exception>

#include "iaito-plugin/core_plugin.h"
#include "r2plugin/r2retdec.h"

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
	RCodeMeta * code = nullptr;

	try {
		code = retdec::r2plugin::decompile(Core()->core(), addr);
	}
	catch (const std::exception& e) {
		code = r_codemeta_new((std::string("decompilation error: ")+e.what()).c_str());
	}
	catch (...) {
		code = nullptr;
	}

	if (code == nullptr)
		code = r_codemeta_new("decompilation error: unable to decompile function at this offset");

	emit finished(code);
}
