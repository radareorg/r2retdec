#include "r2info.h"
#include "r2utils.h"

using namespace retdec;
using namespace common;
using namespace config;
using namespace r2plugin;

std::map<const std::string, const CallingConventionID> R2InfoProvider::_r2rdcc = {
	{"arm32", CallingConventionID::CC_ARM},
	{"arm64", CallingConventionID::CC_ARM64},

	{"n32", CallingConventionID::CC_MIPS},

	{"powerpc-32", CallingConventionID::CC_POWERPC},
	{"powerpc-64", CallingConventionID::CC_POWERPC64},

	{"amd64", CallingConventionID::CC_X64},
	{"ms", CallingConventionID::CC_X64},

	{"borland", CallingConventionID::CC_PASCAL},
	{"cdecl", CallingConventionID::CC_CDECL},
	{"cdecl-thiscall-ms", CallingConventionID::CC_THISCALL},
	{"fastcall", CallingConventionID::CC_FASTCALL},
	{"pascal", CallingConventionID::CC_PASCAL},
	{"stdcall", CallingConventionID::CC_STDCALL},
	{"watcom", CallingConventionID::CC_WATCOM}
};

R2InfoProvider::R2InfoProvider(RCore &core):
	_r2core(core)
{
}

std::string R2InfoProvider::fetchFilePath() const
{
	return _r2core.file->binb.bin->file;
}

Function R2InfoProvider::fetchCurrentFunction() const
{
	RAnalFunction *cf = r_anal_get_fcn_in(_r2core.anal, _r2core.offset, R_ANAL_FCN_TYPE_NULL);
	if (cf == nullptr) {
		std::ostringstream errMsg;
		errMsg << "no function at offset 0x" << std::hex << _r2core.offset;
		throw DecompilationError(errMsg.str());
	}

	return convertFunctionObject(*cf);
}

void R2InfoProvider::fetchFunctions(Config &rconfig) const
{
	auto list = r_anal_get_fcns(_r2core.anal);
	if (list == nullptr)
		return;

	FunctionContainer functions;
	for (RListIter *it = list->head; it; it = it->n) {
		auto fnc = reinterpret_cast<RAnalFunction*>(it->data);
		if (fnc == nullptr)
			continue;
		
		functions.insert(convertFunctionObject(*fnc));
	}

	rconfig.functions = functions;
}

Function R2InfoProvider::convertFunctionObject(RAnalFunction &r2fnc) const
{
	auto start = r_anal_function_min_addr(&r2fnc);
	auto end = r_anal_function_max_addr(&r2fnc);

	Function function(start, end, r2fnc.name);
	function.setRealName(r2fnc.name);
	function.setStartLine(start);
	function.setEndLine(end);

	fetchFunctionLocalsAndArgs(function, r2fnc);
	fetchFunctionCallingconvention(function, r2fnc);
	fetchFunctionReturnType(function, r2fnc);

	// TODO: set variadic

	return function;
}

void R2InfoProvider::fetchFunctionLocalsAndArgs(Function &function, RAnalFunction &r2fnc) const
{
	CTypeConverter tcv;

	auto list = r_anal_var_all_list(_r2core.anal, &r2fnc);
	ObjectSetContainer locals;
	ObjectSequentialContainer args;
	for (RListIter *it = list->head; it; it = it->n) {
		auto locvar = reinterpret_cast<RAnalVar*>(it->data);
		if (locvar == nullptr)
			continue;

		Storage variableStorage;
		switch (locvar->kind) {
		case R_ANAL_VAR_KIND_REG:
			variableStorage = Storage::inRegister(locvar->regname);
			break;
		case R_ANAL_VAR_KIND_SPV:
		case R_ANAL_VAR_KIND_BPV:
			variableStorage = Storage::onStack(locvar->delta);
			//TODO: it is possible, that we must do an extre POP x86: 8 -> 4 (x64: 8 -> 0)
			break;
		default:
			continue;
		};

		Object var(locvar->name, variableStorage);
		var.type = Type(tcv.convert(locvar->type));

		if (locvar->isarg) 
			args.push_back(var);
		else
			locals.insert(var);
	}

	function.locals = locals;
	function.parameters = args;
}

void R2InfoProvider::fetchFunctionCallingconvention(Function &function, RAnalFunction &r2fnc) const
{
	if (r2fnc.cc != nullptr) {
		if (_r2rdcc.count(r2fnc.cc)) {
			function.callingConvention = _r2rdcc[r2fnc.cc];
			return;
		}
	}

	function.callingConvention = CallingConventionID::CC_UNKNOWN;
}

void R2InfoProvider::fetchFunctionReturnType(Function &function, RAnalFunction &r2fnc) const
{
	CTypeConverter tcv;

	if (auto returnType = r_type_func_ret(_r2core.anal->sdb_types, r2fnc.name)) {
		function.returnType = Type(tcv.convert(returnType));
		return;
	}

	function.returnType = Type("void");
}

