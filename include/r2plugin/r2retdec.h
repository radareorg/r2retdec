/**
 * @file include/r2plugin/r2retdec.h
 * @brief Main module of the retdec-r2plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef R2PLUGIN_R2RETDEC_H
#define R2PLUGIN_R2RETDEC_H

#include <r_util/r_annotated_code.h>
#include <r_core.h>

#include "r2plugin/r2info.h"

namespace retdec {
namespace r2plugin {

R_API RAnnotatedCode* decompile(RCore *core, ut64 addr);

}
}

#endif //R2PLUGIN_R2RETDEC_H
