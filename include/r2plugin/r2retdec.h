/**
 * @file include/r2plugin/core_plugin.h
 * @brief Main module of the retdec-r2plugin.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef R2PLUGIN_R2RETDEC_H
#define R2PLUGIN_R2RETDEC_H

#include <r_util/r_annotated_code.h>
#include <r_core.h>

#include "r2plugin/r2info.h"

R_API RAnnotatedCode* decompile(const retdec::r2plugin::R2InfoProvider &binInfo);

#endif //R2PLUGIN_R2RETDEC_H
