#include <algorithm>
#include <cstring>
#include <functional>
#include <fstream>
#include <iterator>
#include <mutex>

#include <r_core.h>
#include <retdec/retdec/retdec.h>
#include <retdec/utils/binary_path.h>
#include <retdec/utils/io/log.h>
#include <retdec/config/config.h>
#include <retdec/config/parameters.h>
#include <sstream>

#include "r2plugin/r2retdec.h"
#include "r2plugin/r2cgen.h"
#include "r2plugin/r2utils.h"

#include "decompiler-config.h"

#include "r2plugin/r2retdec.h"

using fu = retdec::r2plugin::FormatUtils;
using namespace retdec::utils::io;

namespace retdec {
namespace r2plugin {

/**
 * Fetches the directory for output to be saved to.
 *
 * User can specify DEC_SAVE_DIR environment variable to dynamically
 * customize behavior of this function.
 *
 * If DEC_SAVE_DIR is not specified the temporary direcotry is returned
 * by calling fs::temp_directory_path.
 *
 * @throws DecompilationError In case when no the provided directory does
 *                            not exist or it is not possible to create
 *                            temporary directory DecompilationError is
 *                            thrown.
 */
fs::path getOutDirPath(const fs::path &suffix)
{
	std::error_code err;

	auto outDirRaw = getenv("DEC_SAVE_DIR");
	std::string outDir(outDirRaw != nullptr ? outDirRaw : "");
	if (!outDir.empty()) {
		auto outDirPath = fs::path(outDir);
		if (!is_directory(outDirPath, err)) {
			throw DecompilationError(
				"invalid $DEC_SAVE_DIR: not a directory: "
				+outDir
			);
		}

		if (!suffix.empty()) {
			outDirPath /= suffix;
			fs::create_directories(outDirPath);
		}

		return outDirPath;
	}

	auto tmpDir = fs::temp_directory_path(err);

	if (tmpDir.string() == "") {
		// This is a fallback solution for situation when user does
		// not have TMPDIR environment variable set. In this case the
		// standard function `temp_directory_path` seems to not
		// be able to find the /tmp directory and thus return
		// empty string with error code. This was reported
		// to happen only on linux systems with standard /tmp
		// directory and only when this method is called from r2 console.
		tmpDir = fs::path("/tmp");
		if (!is_directory(tmpDir, err)) {
			throw DecompilationError(
				"cannot find a temporary directory on the system. "
				"Please specify a temporary directory by setting "
				"$TMPDIR, or $DEC_OUT_DIR."
			);
		}
	}

	if (!suffix.empty()) {
		tmpDir /= suffix;
		fs::create_directories(tmpDir);
	}

	return tmpDir;
}

/**
 * @brief Reads hash from file provided as parameter.
 */
std::string loadHashString(const fs::path& cachePath)
{
	std::string cacheFileString;

	if (!fs::is_regular_file(cachePath))
		return "";

	std::ifstream cacheFile(cachePath);

	cacheFile >> cacheFileString;

	cacheFile.close();
	return cacheFileString;
}

/**
 * @brief Constructs hash from RD config.
 */
void constructHash(const retdec::config::Config& config, std::ostream& hash)
{
	// RetDec automatically sets time and date to the JSON
	// config. This is not really wanted as each change of time
	// or date will trigger decompilation. Until RetDec provides
	// API without this we need to manually set time and date
	// to constant string.
	rapidjson::Document d;
	d.Parse(config.generateJsonString());

	d["time"].SetString("removed");
	d["date"].SetString("removed");
	d["decompParams"].SetString("removed");

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	d.Accept(writer);

	hash << std::hex << std::hash<std::string>{}(buffer.GetString());
}

fs::path getHashPath(const fs::path& configPath)
{
	return fs::path(configPath).replace_filename(".rd_hash");
}

/**
 * @brief Checks if cached files are up to date.
 */
bool usableCacheExists(const retdec::config::Config& config)
{
	fs::path configPath(config.parameters.getOutputConfigFile());

	if (!fs::is_regular_file(configPath))
		return false;

	std::ostringstream currHash;
	constructHash(config, currHash);

	std::string savedHash = loadHashString(getHashPath(configPath));

	return currHash.str() == savedHash;
}

/**
 * @brief Creates file containng hash constructed from RD config.
 */
void createConfigHashFile(const retdec::config::Config& config)
{
	fs::path configPath(config.parameters.getOutputConfigFile());
	fs::path hashPath = getHashPath(configPath);
	std::ofstream hashFile(hashPath);
	constructHash(config, hashFile);
	hashFile.close();
}

/**
 * @brief Tries to find and load default RetDec configuration file.
 *
 * Default configuration is installed with this plugin on default
 * location.
 */
retdec::config::Config loadDefaultConfig()
{
	// Perhaps support signatures are installed in R2_HOME_PLUGDIR?
	auto plugdir = r_str_home(R2_HOME_PLUGINS);

	// Loads configuration from file - also contains default config.
	auto rdConf = retdec::config::Config::fromJsonString(DefaultConfigJSON);
	// Paths to the signatures, etc.
	rdConf.parameters.fixRelativePaths(plugdir);

	return rdConf;
}

std::string cacheName(const common::Function& fnc)
{
	std::ostringstream hexAddr;
	hexAddr << std::hex << fnc.getStart();
	return fnc.getName()+"@"+hexAddr.str();
}

config::Config createConfig(const R2Database& binInfo, const std::string& cacheSuffix)
{
	auto config = loadDefaultConfig();

	// Fetch binary name -> will be used for caching
	std::string binName = binInfo.fetchFilePath();

	// Create hex from bin name
	std::ostringstream str;
	str << std::hex << std::hash<std::string>{}(binName);

	// Function is identified as : NAME@HEX_ADDR
	auto outName = fs::path(str.str())/cacheSuffix;

	auto outDir = getOutDirPath(outName);

	auto decpath = outDir/"rd_dec.json";
	auto outpath = outDir/"rd_out.log";
	auto errpath = outDir/"rd_err.log";
	auto outconfig = outDir/"rd_config.json";

	config.parameters.setInputFile(binInfo.fetchFilePath());
	config.parameters.setOutputFile(decpath.string());
	config.parameters.setOutputConfigFile(outconfig.string());
	config.parameters.setOutputFormat("json-human");
	config.parameters.setIsVerboseOutput(true);
	config.parameters.setLogFile(outpath.string());
	config.parameters.setErrFile(errpath.string());

	return config;
}

std::pair<RCodeMeta*, retdec::config::Config> decompile(
		config::Config& config,
		bool useCache)
{
	try {
		if (useCache && usableCacheExists(config)) {
			R2CGenerator outgen;
			return {outgen.generateOutput(config.parameters.getOutputFile()), config};
		}
		else {
			createConfigHashFile(config);
		}

		// Interface uses non-const config.

		if (auto rc = retdec::decompile(config)) {
			// Note:
			//   RetDec sets Loggers in decompile function based on settings in config.
			//   After this function ends we want to print out on stdout/stderr again.
			Log::set(Log::Type::Info, Logger::Ptr(new Logger(std::cout)));
			Log::set(Log::Type::Error, Logger::Ptr(new Logger(std::cerr)));

			throw DecompilationError(
				"decompilation ended with error code "
				+ std::to_string(rc) +
				"for more details check " + config.parameters.getErrFile()
			);
		}

		// See note above.
		Log::set(Log::Type::Info, Logger::Ptr(new Logger(std::cout)));
		Log::set(Log::Type::Error, Logger::Ptr(new Logger(std::cerr)));

		R2CGenerator outgen;
		return {outgen.generateOutput(config.parameters.getOutputFile()), config};
	}
	catch (const std::exception &err) {
		Log::set(Log::Type::Info, Logger::Ptr(new Logger(std::cout)));
		Log::set(Log::Type::Error, Logger::Ptr(new Logger(std::cerr)));
		Log::error() << "decompilation error: " << err.what() << std::endl;
	}
	catch (...) {
		Log::set(Log::Type::Info, Logger::Ptr(new Logger(std::cout)));
		Log::set(Log::Type::Error, Logger::Ptr(new Logger(std::cerr)));
		Log::error() << "an unknown decompilation error occurred" << std::endl;
	}

	return {nullptr, retdec::config::Config::empty()};
}

/**
 * This function is to get RCodeMeta to pass it to Cutter's decompiler widget.
 */
R_API RCodeMeta* decompile(RCore *core, ut64 addr){
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock (mutex);

	R2Database binInfo(*core);

	auto fnc = binInfo.fetchFunction(addr);
	auto config = createConfig(binInfo, cacheName(fnc));
	config.parameters.selectedRanges.insert(fnc);
	config.parameters.setIsSelectedDecodeOnly(true);

	binInfo.fetchFunctionsAndGlobals(config);

	auto [code, _] = decompile(config, true);
	return code;
}

}
}
