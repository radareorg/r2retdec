/**
 * @file include/r2plugin/r2info.h
 * @brief Information gathering from R2 and user.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef RETDEC_R2PLUGIN_R2_INFO_H
#define RETDEC_R2PLUGIN_R2_INFO_H

#include <exception>
#include <map>
#include <string>

#include <r_core.h>
#include <r_anal.h>

#include <retdec/config/config.h>

namespace retdec {
namespace r2plugin {

/**
 * R2InfoProvider implements wrapper around R2 API functions.
 */
class R2InfoProvider {
public:
	R2InfoProvider(RCore &core);

public:
	std::string fetchFilePath() const;

	common::Function fetchFunction(ut64 addr) const;	
	common::Function fetchSeekedFunction() const;	

	void fetchFunctionsAndGlobals(config::Config &rdconfig) const;

	void fetchFunctionLocalsAndArgs(common::Function &function, RAnalFunction &r2fnc) const;
	void fetchFunctionCallingconvention(common::Function &function, RAnalFunction &r2fnc) const;
	void fetchFunctionReturnType(common::Function &function, RAnalFunction &r2fnc) const;
	size_t fetchWordSize() const;

protected:
	void fetchGlobals(config::Config &rdconfig) const;
	common::Function convertFunctionObject(RAnalFunction &fnc) const;
	void fetchExtraArgsData(common::ObjectSequentialContainer &args, RAnalFunction &r2fnc) const;

private:
	RCore &_r2core;
	static std::map<const std::string, const common::CallingConventionID> _r2rdcc;
};

class DecompilationError: public std::exception {
public:
	DecompilationError(const std::string &msg) : _message(msg) {}
	~DecompilationError() throw() {}
	const char* what() const throw() { return _message.c_str(); }

private:
	std::string _message;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2_INFO_H*/
