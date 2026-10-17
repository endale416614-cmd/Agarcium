#include <iostream>
#include <memory>
#include "xml_hook.h"
#include "hook.h"
#include <MinHook.h>
#include <tinyxml.h>
#include "mod_loader.h"

namespace xml_hook {
	class CFileSystem {
	public:
		bool ReadXMLFile(TiXmlDocument* xmlHandle, char* filePath, int flags);
	};

	typedef bool(__thiscall* ReadXMLFile_t)(CFileSystem*, TiXmlDocument*, char*, int);
	static ReadXMLFile_t OriginalReadXMLFile = nullptr;
	static ReadXMLFile_t _ReadXMLFile = nullptr;

	BOOL ReadXmlHandle(TiXmlDocument* xmlHandle, char* filePath) {
		if (!filePath) {
			return false;
		}

		std::string foundModId;
		auto& loader = ModLoader::Instance();
		TiXmlDocument* modHandle = loader.GetXmlByRelPath(filePath, &foundModId);

		if (modHandle == nullptr) {
			// No mods for this file
			return false;
		}
		// The mod document is only a source to copy from (InsertEndChild deep-copies); free it on every path.
		std::unique_ptr<TiXmlDocument> modDocument(modHandle);

		// Check the mod file first: a wrong root or empty file must fall back to the original XML.
		TiXmlNode* modMs2Node = modHandle->FirstChild("ms2");
		if (!modMs2Node) {
			std::cerr << "[MODLOADER] mod file has no <ms2> root: " << modHandle->Value() << std::endl;
			return false;
		}

		// Delete the <ms2> node on xmlHandle
		TiXmlNode* ms2Node = xmlHandle->FirstChild("ms2");
		if (ms2Node) {
			xmlHandle->RemoveChild(ms2Node);
		}

		// Append the <ms2> node from modHandle to xmlHandle
		TiXmlNode* newNode = xmlHandle->InsertEndChild(*modMs2Node);
		if (!newNode) {
			std::cerr << "[MODLOADER] Failed to insert ms2 node from modHandle." << std::endl;
			return false;
		}

		// TODO: improved merging for ie. korItemDescription

		return true;
	}

	BOOL __stdcall HookedReadXMLFile(CFileSystem* thisPtr, TiXmlDocument* xmlHandle, char* filePath, int flags) {
		bool bLoaded = ReadXmlHandle(xmlHandle, filePath);

		if (!bLoaded) {
			bLoaded = _ReadXMLFile(thisPtr, xmlHandle, filePath, flags);
		}

		if (!bLoaded) {
			std::cerr << "Failed to load XML file: " << filePath << std::endl;
		}

		return bLoaded;
	}

	BOOL Hook_ReadXMLFile(BOOL bEnable) {
		OriginalReadXMLFile = (ReadXMLFile_t)0x1402a9af0;

		if (MH_CreateHook((PVOID)OriginalReadXMLFile, (PVOID)HookedReadXMLFile,
			reinterpret_cast<LPVOID*>(&_ReadXMLFile)) != MH_OK) {
			std::cerr << "Failed to hook XML" << std::endl;
			return false;
		}

		if (MH_EnableHook((PVOID)OriginalReadXMLFile) != MH_OK) {
			std::cerr << "Failed to enable XML hook" << std::endl;
			return false;
		}

		return true;
	}

	BOOL init() {
		Hook_ReadXMLFile(TRUE);
		return true;
	}
}
