/**
 * @file src/r2plugin/r2data.cpp
 * @brief Information gathering from R2 and user.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <retdec/utils/io/log.h>

#include "r2plugin/r2data.h"
#include "r2plugin/r2utils.h"

using namespace retdec::common;
using namespace retdec::config;
using namespace retdec::r2plugin;
using fu = retdec::r2plugin::FormatUtils;
using retdec::utils::io::Log;

/**
 * Translation map between tokens representing calling convention type returned
 * by Radare2 and CallingConventionID that is recognized by RetDec.
 */
std::map<const std::string, const CallingConventionID> R2Database::_r2rdcc = {
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

R2Database::R2Database(RCore &core):
	_r2core(core)
{
}

/**
 * @brief Fetches path of the binary file from Radare2.
 */
std::string R2Database::fetchFilePath() const
{
	return _r2core.file->binb.bin->file;
}

void R2Database::setFunction(const common::Function &fnc) const
{
	auto r2fnc = r_anal_get_function_at(_r2core.anal, fnc.getStart().getValue());
	if (r2fnc == nullptr) {
		r2fnc = r_anal_create_function(_r2core.anal, fnc.getName().c_str(),
				fnc.getStart().getValue(), R_ANAL_FCN_TYPE_FCN, nullptr);
		if (r2fnc == nullptr) {
			throw DecompilationError("Unable to create function on address "
					+ std::to_string(fnc.getStart().getValue()));
		}
	}

	if (!fnc.isDynamicallyLinked() && fnc.getSize().getValue() > 1)
		if (!r_anal_fcn_add_bb(_r2core.anal, r2fnc, fnc.getStart().getValue(), fnc.getSize().getValue(), UT64_MAX, UT64_MAX, nullptr))
			Log::error() << Log::Warning << "unable to add basic block of " << fnc.getName() << std::endl;

	copyFunctionData(fnc, *r2fnc);
}

std::string sanitize(const std::string& a)
{
	std::ostringstream ok;
	for (auto& c: a)
		if (c != '$' && c != '@')
			ok << c;

	return ok.str();
}

void R2Database::copyFunctionData(const common::Function &fnc, RAnalFunction &r2fnc) const
{
	if (r_anal_function_rename(&r2fnc, fnc.getName().c_str()) == false) {
		std::ostringstream err;
		err << "unable to set rename function at offset "
			<< std::hex << fnc.getStart() << ": new name \"" << fnc.getName();
		throw DecompilationError(err.str());
	}

	// TODO:
	//   - Provide "hack":
	//     Get/Create declaration string. When such string is available provide "sanitization".
	//     Sanitization will check for symbols that r2 cannot parse and replace them with
	//     more appropriate symbols.
	if (false && !fnc.getDeclarationString().empty()) {
		r_anal_str_to_fcn(_r2core.anal, &r2fnc, (fnc.getDeclarationString()+";").c_str());
	}
	else {
		std::ostringstream data;
		data << fu::convertLlvmTypeToC(fnc.returnType.getLlvmIr()) << " "
			<< fnc.getName() << "(";

		if (!fnc.parameters.empty()) {
			data << fu::convertLlvmTypeToC(fnc.parameters.front().type.getLlvmIr());
			data << " " << fnc.parameters.front().getName();
		}
		for (auto& a: fnc.parameters) {
			data << ", " << fu::convertLlvmTypeToC(a.type.getLlvmIr())
				<< " " << a.getName();
		}
		data << ");";
		r_anal_str_to_fcn(_r2core.anal, &r2fnc, sanitize(data.str()).c_str());
	}

}

void R2Database::setFunctions(const config::Config& config) const
{
	for (auto& fnc: config.functions) {
		setFunction(fnc);
	}
}

/**
 * @brief Fetches the function at the address passed as parameter.
 *
 * @param addr Analyzes the function at the given address.
 */
Function R2Database::fetchFunction(ut64 addr) const
{
	RAnalFunction *cf = r_anal_get_fcn_in(_r2core.anal, addr, R_ANAL_FCN_TYPE_NULL);
	if (cf == nullptr) {
		std::ostringstream errMsg;
		errMsg << "no function at offset 0x" << std::hex << addr;
		throw DecompilationError(errMsg.str());
	}

	return convertFunctionObject(*cf);
}

Function R2Database::fetchSeekedFunction() const
{
	return fetchFunction(_r2core.offset);
}

/**
 * @brief Fetches functions and global variables from Radare2.
 */
void R2Database::fetchFunctionsAndGlobals(Config &rconfig) const
{
	auto list = r_anal_get_fcns(_r2core.anal);
	if (list != nullptr) {
		FunctionContainer functions;
		for (RListIter *it = list->head; it; it = it->n) {
			auto fnc = reinterpret_cast<RAnalFunction*>(it->data);
			if (fnc == nullptr)
				continue;
			functions.insert(convertFunctionObject(*fnc));
		}

		rconfig.functions = functions;
	}
	fetchGlobals(rconfig);
}

/**
 * @brief Fetches global variables from the Radare2.
 *
 * This method is intended only for internal usage. That is
 * why this method is private. To obtain functions and global
 * variables the R2Database::fetchFunctionsAndGlobals
 * method is available.
 *
 * Reason for this is that currently the global variables are
 * not supported in Radare2 and fetching them requires sort
 * of hack by looking into all available symbols and flags.
 * User may spacify symbol or provide flag on a specified address
 * and that could be treated as presence of global variable in
 * some cases.
 *
 * While browsing flags and symbols this method provides correction
 * of fetched functions as some of them might be dynamically linked.
 * This is another reason why this method is private and interface
 * to fetch globals is integrated with interface to fetch functions.
 */
void R2Database::fetchGlobals(Config &config) const
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

		// If type is FUNC and flag is set to true
		// the function should be checked wheter it
		// was not fetched and should be corrected.
		//
		// In future this code should be moved to the fetch
		// functions method. As this function is private
		// and this is the intended usage for now I decided
		// to let it here.
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
		// Sometimes when setting flag, the type automatically is set to FUNC.
		if (bind == "GLOBAL" && (type == "FUNC" || type == "OBJ")) {
			if (config.functions.count(name) || config.functions.count("imp."+name)
					|| sym->vaddr == 0) {
				// This is a function, not a global variable.
				continue;
			}
			// Flags will contain custom name set by user.
			RFlagItem* flag = r_flag_get_i(_r2core.flags, sym->vaddr);
			if (flag) {
				name = flag->name;
			}

			Object var(name, Storage::inMemory(sym->vaddr));
			var.setRealName(name);

			globals.insert(var);
		}
	}

	// If we found at least one dynamically linked function.
	if (!functions.empty()) {
		for (auto f: config.functions) {
			functions.insert(f);
		}
		config.functions = std::move(functions);
	}

	config.globals = globals;
}

/**
 * Converts function object from its representation in Radare2 into
 * represnetation that is used in RetDec.
 */
Function R2Database::convertFunctionObject(RAnalFunction &r2fnc) const
{
	auto start = r_anal_function_min_addr(&r2fnc);
	auto end = r_anal_function_max_addr(&r2fnc);

	auto name = fu::stripName(r2fnc.name);

	Function function(start, end, name);

	function.setIsUserDefined();
	fetchFunctionReturnType(function, r2fnc);
	fetchFunctionCallingconvention(function, r2fnc);
	fetchFunctionLocalsAndArgs(function, r2fnc);

	return function;
}

/**
 * Fetches local variables and arguments of a functon.
 *
 * As there are more types of storage of arguments they can be fetched from multiple sources
 * in radare2. this is the reason why there is only one interface for fetching arguments and
 * local variables.
 *
 * When user do not provide argument for a function and the function has calling convention
 * that does not use registers (cdecl), the aruments are are deducted in r2 based on the offset.
 * This is not, however, projected into function's calling convention and the args are needed to
 * be fetched with stack variables of the funciton.
 */
void R2Database::fetchFunctionLocalsAndArgs(Function &function, RAnalFunction &r2fnc) const
{
	ObjectSetContainer locals;
	ObjectSequentialContainer r2args, r2userArgs;

	auto list = r_anal_var_all_list(_r2core.anal, &r2fnc);
	if (list != nullptr) {
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
			var.type = Type(fu::convertTypeToLlvm(locvar->type));
			var.setRealName(locvar->name);

			// If variable is argument it is a local variable too.
			if (locvar->isarg)
				r2args.push_back(var);

			locals.insert(var);
		}
	}

	fetchExtraArgsData(r2userArgs, r2fnc);

	function.locals = locals;

	// User spevcified arguments must have higher priority
	function.parameters = r2userArgs.empty() ? r2args : r2userArgs;
}

/**
 * @brief Fetches function arguments defined by user.
 */
void R2Database::fetchExtraArgsData(ObjectSequentialContainer &args, RAnalFunction &r2fnc) const
{
	RAnalFuncArg *arg;

	char* key = resolve_fcn_name(_r2core.anal, r2fnc.name);
	if (!key || !_r2core.anal|| !_r2core.anal->sdb_types)
		return;

	int nargs = r_type_func_args_count(_r2core.anal->sdb_types, key);
	if (nargs) {
		RList *list = r_core_get_func_args(&_r2core, r2fnc.name);
		for (RListIter *it = list->head; it; it = it->n) {
			arg = reinterpret_cast<RAnalFuncArg*>(it->data);
			Object var(arg->name, Storage::undefined());
			var.setRealName(arg->name);
			var.type = Type(fu::convertTypeToLlvm(arg->orig_c_type));
			args.push_back(var);
		}
		r_list_free (list);
	}
}

/**
 * @brief Fetches the calling convention of the input function from Radare2.
 */
void R2Database::fetchFunctionCallingconvention(Function &function, RAnalFunction &r2fnc) const
{
	if (r2fnc.cc != nullptr) {
		if (_r2rdcc.count(r2fnc.cc)) {
			function.callingConvention = _r2rdcc[r2fnc.cc];
			return;
		}
	}

	function.callingConvention = CallingConventionID::CC_UNKNOWN;
}

/**
 * @brief Fetches the return type of the input function from Radare2.
 */
void R2Database::fetchFunctionReturnType(Function &function, RAnalFunction &r2fnc) const
{
	function.returnType = Type("void");
	char* key = resolve_fcn_name(_r2core.anal, r2fnc.name);

	if (!key || !_r2core.anal || !_r2core.anal->sdb_types)
		return;

	if (auto returnType = r_type_func_ret(_r2core.anal->sdb_types, key))
		function.returnType = Type(fu::convertTypeToLlvm(returnType));
}

/**
 * @brief Fetch word size of the input file architecture.
 */
size_t R2Database::fetchWordSize() const
{
	return r_config_get_i(_r2core.config, "asm.bits");
}

ut64 R2Database::seekedAddress() const
{
	return _r2core.offset;
}

const RCore& R2Database::core() const
{
	return _r2core;
}
