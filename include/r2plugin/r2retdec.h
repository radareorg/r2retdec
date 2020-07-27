#ifndef R2RETDEC_H
#define R2RETDEC_H

#include <r_util/r_annotated_code.h>
#include <r_core.h>

RAnnotatedCode* r2retdec_decompile_annotated_code(RCore *core, ut64 addr);

#endif //R2RETDEC_H
