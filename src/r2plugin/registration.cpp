/**
 * @file src/r2plugin/registration.cpp
 * @brief Module that implements registration logic to r2 console.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <mutex>

#include <retdec/utils/io/log.h>
#include <r_core.h>

#include "r2plugin/r2data.h"
#include "r2plugin/console/decompiler.h"

using namespace retdec::r2plugin;
using namespace retdec::utils::io;

/**
 * R2 console registration method. This method is called
 * after each command typed into r2. If the function wants
 * to respond on provided command, provides response and returns true.
 * Activation method for this function is matching prefix of the input.
 *  -> prefix(input) == CMD_PREFIX
 *
 * Otherwise the function must return false which will indicate that
 * other command should be executed.
 */
static int r2retdec_cmd(void *user, const char* input)
{
	static std::mutex mutex;
	RCore& core = *(RCore*)user;
	R2Database binInfo(core);

	try {
		std::lock_guard<std::mutex> lock (mutex);
		return DecompilerConsole::handleCommand(std::string(input), binInfo);
	}
	catch (const std::exception& e) {
		Log::error() << Log::Error << e.what() << std::endl;
		return true;
	}
}

// Structure containing plugin info.
RCorePlugin r_core_plugin_retdec = {
	/* .name = */ "r2retdec",
	/* .desc = */ "RetDec integration",
	/* .license = */ "MIT",
	/* .author = */ "Avast",
	/* .version = */ "0.4.0",
	/* .call = */ r2retdec_cmd,
	/* .init = */ nullptr,
	/* .fini = */ nullptr
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif

// This will register the r2plugin in r2 console.
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_CORE,
	/* .data = */ &r_core_plugin_retdec,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr,
	/* .pkgname */ "retdec-r2plugin"
};

#endif
