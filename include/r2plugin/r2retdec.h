/**
 * @file include/r2plugin/r2retdec.h
 * @brief Main module of the retdec-r2plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef R2PLUGIN_R2RETDEC_H
#define R2PLUGIN_R2RETDEC_H

#include <r_codemeta.h>
#include <r_core.h>

#include "r2plugin/r2data.h"
#include "filesystem_wrapper.h"

namespace retdec {
namespace r2plugin {

R_API RCodeMeta* decompile(RCore *core, ut64 addr);

std::pair<RCodeMeta*, retdec::config::Config> decompile(
		const R2Database &binInfo,
		const common::AddressRange& decompileRange,
		bool useCache = true,
		bool fetchR2Data = true);

std::pair<RCodeMeta*, retdec::config::Config> decompile(
		config::Config& config,
		bool useCache);

config::Config createConfig(const R2Database& binInfo, const std::string& cacheSuffix = "");

std::string cacheName(const common::Function& fnc);

fs::path getOutDirPath(const fs::path &suffix = "");

}
}


#endif //R2PLUGIN_R2RETDEC_H
