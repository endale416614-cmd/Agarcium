#include "mod_loader.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include "config.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

ModLoader& ModLoader::Instance() {
	static ModLoader instance;
	return instance;
}

const std::map<std::string, ModInfo>& ModLoader::GetMods() const {
	return mods_;
}

void ModLoader::Clear() {
	mods_.clear();
}

static std::string read_file(const fs::path& path) {
	std::ifstream file(path, std::ios::binary);
	if (!file) throw std::runtime_error("Cannot open file: " + path.string());
	return std::string((std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());
}

static std::string ToLower(const std::string& s) {
	std::string out = s;
	std::transform(out.begin(), out.end(), out.begin(),
		[](unsigned char c) { return std::tolower(c); });
	return out;
}

bool ModLoader::LoadMods(const std::string& modsRootPath) {
	Clear();
	try {
		for (const auto& entry : fs::directory_iterator(modsRootPath)) {
			if (entry.is_directory()) {
				ParseMod(entry.path().string());
			}
		}

		// mods_ is ordered by id and GetXmlByRelPath takes the first match, so the first mod wins.
		// Only XML files are served by the hook; other shared names (mod.json, ...) are not conflicts.
		std::map<std::string, std::string> winners;
		for (const auto& [modId, modInfo] : mods_) {
			for (const auto& [key, rel] : modInfo.files) {
				if (!key.ends_with(".xml")) continue;
				auto [it, inserted] = winners.emplace(key, modId);
				if (!inserted) {
					std::cerr << "[MODLOADER] " << rel << " provided by " << it->second
						<< " and " << modId << "; using " << it->second << std::endl;
				}
			}
		}

		std::cout << "[MODLOADER] Loaded " << mods_.size() << " mods." << std::endl;

		return true;
	}
	catch (...) {
		Clear();
		return false;
	}
}

bool ModLoader::ParseMod(const std::string& modFolderPath) {
	try {
		fs::path modPath = modFolderPath;
		fs::path modJsonPath = modPath / "mod.json";
		if (!fs::exists(modJsonPath)) return false;

		std::string json_str = read_file(modJsonPath);
		json mod_info_json = json::parse(json_str);
		std::string mod_id = mod_info_json.value("id", "");

		if (mod_id.empty()) return false;

		ModInfo modInfo;
		modInfo.id = mod_id;

		std::cout << "[MODLOADER] Loading mod: " << mod_id << std::endl;

		for (auto& p : fs::recursive_directory_iterator(modPath)) {
			if (p.is_regular_file()) {
				fs::path rel = fs::relative(p.path(), modPath);
				std::string relStr = rel.generic_string();
				std::string relLower = ToLower(relStr);

				modInfo.files[relLower] = relStr;
			}
		}

		mods_[mod_id] = std::move(modInfo);
		return true;
	}
	catch (const std::exception& ex) {
		// Optionally log ex.what()
		return false;
	}
}

TiXmlDocument* ModLoader::GetXmlByRelPath(const std::string& relPath, std::string* outModId) const {
    std::string key = ToLower(relPath);

	// replace all \ with /
	std::replace(key.begin(), key.end(), '\\', '/');

	// remove ./ prefix if it exists
	if (key.starts_with("./")) {
		key = key.substr(2);
	}

    for (const auto& [modId, modInfo] : mods_) {
        auto it = modInfo.files.find(key);
        if (it != modInfo.files.end()) {
            if (outModId) *outModId = modId;
			fs::path xmlPath = config::ModsPath / fs::path(modInfo.id) / it->second;
			std::string xmlPathStr = xmlPath.generic_string();
			TiXmlDocument* doc = new TiXmlDocument(xmlPathStr.c_str());
			if (doc->LoadFile()) {
				return doc;
			}
			else {
				std::cerr << "[MODLOADER] Failed to load XML file: " << xmlPathStr << std::endl;
				delete doc;
			}
        }
    }
    return nullptr;
}