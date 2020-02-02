/**
 * @file src/r2info.cpp
 * @brief Information gathering from R2 and user.
 * @copyright (c) 2019 Avast Software, licensed under the LGPLv3 license.
 */

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

void R2InfoProvider::fetchFunctionsAndGlobals(Config &rconfig) const
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
	fetchGlobals(rconfig);
}

void R2InfoProvider::fetchGlobals(Config &config) const
{
	RBinObject *obj = r_bin_cur_object(_r2core.bin);
	if (obj == nullptr || obj->symbols == nullptr)
		return;

	auto list = obj->symbols;
	GlobalVarContainer globals;

	FunctionContainer functions;
	for (RListIter *it = list->head; it; it = it->n) {
		auto sym = reinterpret_cast<RBinSymbol*>(it->data);
		if (sym == nullptr)
			continue;

		std::string type(sym->type);
		std::string name(sym->name);
		std::string bind(sym->bind);
		bool isImported = sym->is_imported;
	
		if (type == "FUNC" && isImported) {
			auto it = config.functions.find(name);
			if (it != config.functions.end()) {
				Function f = *it;
				f.setIsVariadic(true);
				f.setIsDynamicallyLinked();
				functions.insert(f);
			}
			else {
				//TODO: do we want to include these functions?
			}
		}
		if (bind == "GLOBAL" && (type == "FUNC" || type == "OBJ")) {
			if (config.functions.count(name) || config.functions.count("imp."+name)
					|| sym->vaddr == 0) {
				continue;
			}
			RFlagItem* flag = r_flag_get_i(_r2core.flags, sym->vaddr);
			if (flag) {
				name = flag->name;
			}

			Object var(name, Storage::inMemory(sym->vaddr));
			var.setRealName(name);

			globals.insert(var);
		}
	}

	if (!functions.empty()) {
		for (auto f: config.functions) {
			functions.insert(f);
		}
	}

	config.functions = functions;
	config.globals = globals;
}

Function R2InfoProvider::convertFunctionObject(RAnalFunction &r2fnc) const
{
	auto start = r_anal_function_min_addr(&r2fnc);
	auto end = r_anal_function_max_addr(&r2fnc);

	FormatUtils fu;

	auto name = fu.stripName(r2fnc.name);

	Function function(start, end, name);

	fetchFunctionReturnType(function, r2fnc);
	fetchFunctionCallingconvention(function, r2fnc);
	fetchFunctionLocalsAndArgs(function, r2fnc);

	// TODO: set variadic

	return function;
}

void R2InfoProvider::fetchFunctionLocalsAndArgs(Function &function, RAnalFunction &r2fnc) const
{
	FormatUtils fu;

	auto list = r_anal_var_all_list(_r2core.anal, &r2fnc);
	ObjectSetContainer locals;
	ObjectSequentialContainer r2args, r2userArgs;
	for (RListIter *it = list->head; it; it = it->n) {
		auto locvar = reinterpret_cast<RAnalVar*>(it->data);
		if (locvar == nullptr)
			continue;

		Storage variableStorage;
		switch (locvar->kind) {
		case R_ANAL_VAR_KIND_REG: {
			variableStorage = Storage::inRegister(locvar->regname);
		}
		break;
		case R_ANAL_VAR_KIND_SPV:
		case R_ANAL_VAR_KIND_BPV: {
			int stackOffset = locvar->delta;
			// Execute extra pop to match RetDec offset base.
			// extra POP x86: 8 -> 4 (x64: 8 -> 0)
			stackOffset -= fetchWordSize()/8;
			variableStorage = Storage::onStack(stackOffset);
		}
		break;
		default:
			continue;
		};

		Object var(locvar->name, variableStorage);
		var.type = Type(fu.convertTypeToLlvm(locvar->type));
		var.setRealName(locvar->name);

		if (locvar->isarg)
			r2args.push_back(var);

		locals.insert(var);
	}

	fetchExtraArgsData(r2userArgs, r2fnc);

	function.locals = locals;
	function.parameters = r2userArgs.empty() ? r2args : r2userArgs;
}

void R2InfoProvider::fetchExtraArgsData(ObjectSequentialContainer &args, RAnalFunction &r2fnc) const
{
	FormatUtils fu;
	RAnalFuncArg *arg;

	char* key = resolve_fcn_name(_r2core.anal, r2fnc.name);
	int nargs = r_type_func_args_count (_r2core.anal->sdb_types, key);
	if (nargs) {
		RList *list = r_core_get_func_args(&_r2core, r2fnc.name);
		for (RListIter *it = list->head; it; it = it->n) {
			arg = reinterpret_cast<RAnalFuncArg*>(it->data);
			Object var(arg->name, Storage::undefined());
			var.setRealName(arg->name);
			var.type = Type(fu.convertTypeToLlvm(arg->orig_c_type));
			args.push_back(var);
		}
		r_list_free (list);
	}

	free(key);
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
	FormatUtils fu;

	char* key = resolve_fcn_name(_r2core.anal, r2fnc.name);
	if (auto returnType = r_type_func_ret(_r2core.anal->sdb_types, key)) {
		function.returnType = Type(fu.convertTypeToLlvm(returnType));
		free(key);
		return;
	}

	free(key);
	function.returnType = Type("void");
}

size_t R2InfoProvider::fetchWordSize() const
{
	return r_config_get_i(_r2core.config, "asm.bits");
}
