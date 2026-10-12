#pragma once
// Minimal stand-in for ATL::CString so the client patch builds without the ATL component.
// Mirrors ATL's memory layout (CStringData header before the characters) and allocates
// through the string's own IAtlStringMgr, i.e. the game's allocator, exactly like ATL does.
// The client's gLoginUsername/gLoginPassword are narrow (CStringA): writing UTF-16 there
// makes the server read only the first letter.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <cstring>

namespace cstring_lite {
	struct CStringData;

	struct IAtlStringMgr {
		virtual CStringData* Allocate(int nAllocLength, int nCharSize) = 0;
		virtual void Free(CStringData* pData) = 0;
		virtual CStringData* Reallocate(CStringData* pData, int nAllocLength, int nCharSize) = 0;
		virtual CStringData* GetNilString() = 0;
		virtual IAtlStringMgr* Clone() = 0;
	};

	struct CStringData {
		IAtlStringMgr* pStringMgr;
		int nDataLength;
		int nAllocLength;
		long nRefs;

		char* data() { return reinterpret_cast<char*>(this + 1); }
	};

	// A CStringA object is a single pointer to its character data.
	struct CStringA {
		char* m_pszData;

		CStringData* GetData() const { return reinterpret_cast<CStringData*>(m_pszData) - 1; }

		bool SetString(const std::string& value) {
			CStringData* pOld = GetData();
			IAtlStringMgr* pMgr = pOld->pStringMgr;
			int nLength = static_cast<int>(value.size());

			CStringData* pNew = pMgr->Allocate(nLength, sizeof(char));
			if (pNew == nullptr) {
				return false;
			}
			memcpy(pNew->data(), value.c_str(), nLength + 1);
			pNew->nDataLength = nLength;
			m_pszData = pNew->data();

			// Same as CStringData::Release(); locked strings (nRefs < 0) are left alone.
			if (pOld->nRefs > 0 && InterlockedDecrement(&pOld->nRefs) <= 0) {
				pOld->pStringMgr->Free(pOld);
			}
			return true;
		}
	};
}
