#define _WIN32_WINNT 0x0601
#include <winsock2.h>

#include <windows.h>
#include <commctrl.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <set>
#include <cwctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Psapi.lib")

#define IDC_LISTVIEW 1001
#define TIMER_ID 1

HWND hListView;
HIMAGELIST hImageList = NULL;
std::unordered_map<DWORD, std::wstring> pidNameCache;
std::unordered_map<DWORD, int> pidIconIndexCache;

int sortColumn = 0;
bool sortAscending = true;

struct ConnKey {
    DWORD pid;
    std::wstring localAddr;
    std::wstring remoteAddr;
    std::wstring protocol;

    bool operator==(const ConnKey& other) const {
        return pid == other.pid
            && localAddr == other.localAddr
            && remoteAddr == other.remoteAddr
            && protocol == other.protocol;
    }
};

namespace std {
    template<>
    struct hash<ConnKey> {
        std::size_t operator()(const ConnKey& k) const {
            return ((std::hash<DWORD>()(k.pid)
                ^ (std::hash<std::wstring>()(k.localAddr) << 1)) >> 1)
                ^ (std::hash<std::wstring>()(k.remoteAddr) << 1)
                ^ (std::hash<std::wstring>()(k.protocol) << 1);
        }
    };
}

std::unordered_map<ConnKey, int> currentItems;

std::wstring GetProcessNameByPID(DWORD pid) {
    auto it = pidNameCache.find(pid);
    if (it != pidNameCache.end()) {
        return it->second;
    }

    std::wstring processName = L"";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return L"";

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                processName = pe.szExeFile;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    pidNameCache[pid] = processName;
    return processName;
}

std::wstring GetExePathByPID(DWORD pid) {
    std::wstring path(MAX_PATH, L'\0');
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        DWORD size = (DWORD)path.size();
        if (QueryFullProcessImageNameW(hProcess, 0, &path[0], &size)) {
            path.resize(size);
            CloseHandle(hProcess);
            return path;
        }
        CloseHandle(hProcess);
    }
    return L"";
}

int AddProcessIconToImageList(DWORD pid) {
    auto it = pidIconIndexCache.find(pid);
    if (it != pidIconIndexCache.end()) {
        return it->second;
    }

    std::wstring exePath = GetExePathByPID(pid);
    int iconIndex = -1;
    if (!exePath.empty()) {
        HICON hIcon = ExtractIconW(NULL, exePath.c_str(), 0);
        if (hIcon) {
            iconIndex = ImageList_AddIcon(hImageList, hIcon);
            DestroyIcon(hIcon);
        }
    }

    if (iconIndex == -1) {
        iconIndex = 0;
    }

    pidIconIndexCache[pid] = iconIndex;
    return iconIndex;
}

void AddColumnToListView(HWND hwndLV, int iCol, LPCWSTR text, int width) {
    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.pszText = (LPWSTR)text;
    lvc.cx = width;
    lvc.iSubItem = iCol;
    ListView_InsertColumn(hwndLV, iCol, &lvc);
}

std::wstring IpPortToString(DWORD ip, DWORD port) {
    WCHAR ipStr[INET6_ADDRSTRLEN] = { 0 };
    IN_ADDR inAddr;
    inAddr.S_un.S_addr = ip;

    InetNtop(AF_INET, &inAddr, ipStr, INET6_ADDRSTRLEN);

    wchar_t result[256];
    swprintf(result, 256, L"%s:%d", ipStr, ntohs((u_short)port));
    return std::wstring(result);
}

int wcscmpi(const wchar_t* s1, const wchar_t* s2) {
    while (*s1 && *s2) {
        wchar_t c1 = towlower(*s1);
        wchar_t c2 = towlower(*s2);
        if (c1 != c2)
            return c1 - c2;
        s1++;
        s2++;
    }
    return towlower(*s1) - towlower(*s2);
}

int CompareIpPort(const wchar_t* a, const wchar_t* b) {
    wchar_t ipA[64], ipB[64];
    int portA = 0, portB = 0;

    swscanf(a, L"%63[^:]:%d", ipA, &portA);
    swscanf(b, L"%63[^:]:%d", ipB, &portB);

    IN_ADDR addrA = {}, addrB = {};
    InetPton(AF_INET, ipA, &addrA);
    InetPton(AF_INET, ipB, &addrB);

    DWORD ipAInt = ntohl(addrA.S_un.S_addr);
    DWORD ipBInt = ntohl(addrB.S_un.S_addr);

    if (ipAInt < ipBInt) return -1;
    if (ipAInt > ipBInt) return 1;

    if (portA < portB) return -1;
    if (portA > portB) return 1;

    return 0;
}

int FindItemIndexByLPARAM(HWND hwndLV, LPARAM lParam) {
    int count = ListView_GetItemCount(hwndLV);
    LVITEM lvItem = {};
    lvItem.mask = LVIF_PARAM;
    for (int i = 0; i < count; i++) {
        lvItem.iItem = i;
        if (ListView_GetItem(hwndLV, &lvItem) && lvItem.lParam == lParam) {
            return i;
        }
    }
    return -1;
}

int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    int col = (int)lParamSort;

    int index1 = FindItemIndexByLPARAM(hListView, lParam1);
    int index2 = FindItemIndexByLPARAM(hListView, lParam2);

    if (index1 == -1 || index2 == -1)
        return 0;

    wchar_t text1[256], text2[256];
    ListView_GetItemText(hListView, index1, col, text1, 256);
    ListView_GetItemText(hListView, index2, col, text2, 256);

    int cmp = 0;
    if (col == 1 || col == 2) {
        cmp = CompareIpPort(text1, text2);
    }
    else {
        cmp = wcscmpi(text1, text2);
    }

    if (cmp == 0 && col != 0) {
        ListView_GetItemText(hListView, index1, 0, text1, 256);
        ListView_GetItemText(hListView, index2, 0, text2, 256);
        cmp = wcscmpi(text1, text2);
    }

    return sortAscending ? cmp : -cmp;
}

ConnKey MakeConnKey(DWORD pid, const std::wstring& local, const std::wstring& remote, const std::wstring& proto) {
    ConnKey k;
    k.pid = pid;
    k.localAddr = local;
    k.remoteAddr = remote;
    k.protocol = proto;
    return k;
}

void UpdateConnections(HWND hList) {
    std::set<LPARAM> selectedItems;
    int selectedCount = ListView_GetSelectedCount(hList);
    if (selectedCount > 0) {
        int count = ListView_GetItemCount(hList);
        LVITEM lvItem = {};
        lvItem.mask = LVIF_PARAM | LVIF_STATE;
        lvItem.stateMask = LVIS_SELECTED;
        for (int i = 0; i < count; i++) {
            lvItem.iItem = i;
            if (ListView_GetItem(hList, &lvItem) && (lvItem.state & LVIS_SELECTED)) {
                selectedItems.insert(lvItem.lParam);
            }
        }
    }

    std::unordered_map<ConnKey, ConnKey> newConns;

    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
    PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;
    DWORD dwSize = 0;

    GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
    if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
            auto row = pTcpTable->table[i];
            std::wstring local = IpPortToString(row.dwLocalAddr, row.dwLocalPort);
            std::wstring remote = IpPortToString(row.dwRemoteAddr, row.dwRemotePort);
            ConnKey k = MakeConnKey(row.dwOwningPid, local, remote, L"TCP");
            newConns[k] = k;
        }
    }
    free(pTcpTable);

    dwSize = 0;
    GetExtendedUdpTable(NULL, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
    if (GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i) {
            auto row = pUdpTable->table[i];
            std::wstring local = IpPortToString(row.dwLocalAddr, row.dwLocalPort);
            ConnKey k = MakeConnKey(row.dwOwningPid, local, L"", L"UDP");
            newConns[k] = k;
        }
    }
    free(pUdpTable);

    // Remove itens que sumiram
    for (auto it = currentItems.begin(); it != currentItems.end();) {
        if (newConns.find(it->first) == newConns.end()) {
            ListView_DeleteItem(hList, it->second);
            it = currentItems.erase(it);
        }
        else {
            ++it;
        }
    }

    // Reindexa currentItems para refletir o índice no ListView
    currentItems.clear();
    int count = ListView_GetItemCount(hList);
    LVITEM lvItem = {};
    lvItem.mask = LVIF_PARAM;
    for (int i = 0; i < count; i++) {
        lvItem.iItem = i;
        if (ListView_GetItem(hList, &lvItem)) {
            WCHAR textLocal[256], textRemote[256], textProto[256];
            ListView_GetItemText(hList, i, 1, textLocal, 256);
            ListView_GetItemText(hList, i, 2, textRemote, 256);
            ListView_GetItemText(hList, i, 3, textProto, 256);

            DWORD pid = (DWORD)lvItem.lParam;
            ConnKey k = MakeConnKey(pid, textLocal, textRemote, textProto);
            currentItems[k] = i;
        }
    }

    // Adiciona novos itens
    for (const auto& pair : newConns) {
        if (currentItems.find(pair.first) == currentItems.end()) {
            int index = ListView_GetItemCount(hList);
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
            lvi.iItem = index;

            std::wstring pname = GetProcessNameByPID(pair.first.pid);
            lvi.pszText = (LPWSTR)(pname.empty() ? L"(Unknown)" : pname.c_str());
            lvi.iImage = AddProcessIconToImageList(pair.first.pid);
            lvi.lParam = pair.first.pid;

            ListView_InsertItem(hList, &lvi);
            ListView_SetItemText(hList, index, 1, (LPWSTR)pair.first.localAddr.c_str());
            ListView_SetItemText(hList, index, 2, (LPWSTR)pair.first.remoteAddr.c_str());
            ListView_SetItemText(hList, index, 3, (LPWSTR)pair.first.protocol.c_str());

            currentItems[pair.first] = index;
        }
    }

    // Aplica ordenação
    ListView_SortItems(hListView, CompareFunc, (LPARAM)sortColumn);

    // Restaura seleção
    for (auto pid : selectedItems) {
        int idx = FindItemIndexByLPARAM(hList, pid);
        if (idx != -1) {
            ListView_SetItemState(hList, idx, LVIS_SELECTED, LVIS_SELECTED);
        }
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
    {
        INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_WIN95_CLASSES };
        InitCommonControlsEx(&icex);

        hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 10);
        HICON hIcon = LoadIcon(NULL, IDI_APPLICATION);
        ImageList_AddIcon(hImageList, hIcon);

        hListView = CreateWindow(WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHAREIMAGELISTS,
            10, 10, 760, 500, hwnd, (HMENU)IDC_LISTVIEW, NULL, NULL);

        ListView_SetImageList(hListView, hImageList, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        AddColumnToListView(hListView, 0, L"Process Name", 100);
        AddColumnToListView(hListView, 1, L"Local Address", 100);
        AddColumnToListView(hListView, 2, L"Remote Address", 100);
        AddColumnToListView(hListView, 3, L"Protocol", 100);

        // Preenche os itens
        UpdateConnections(hListView);

        // Ajusta a largura das colunas com base no conteúdo (items + header)
        for (int i = 0; i < 4; i++) {
            ListView_SetColumnWidth(hListView, i, LVSCW_AUTOSIZE);
        }

        SetTimer(hwnd, TIMER_ID, 1000, NULL);
    }
    break;

    case WM_SIZE:
        // Apenas redimensiona a ListView, sem alterar largura das colunas
    {
        RECT rcClient;
        GetClientRect(hwnd, &rcClient);

        SetWindowPos(hListView, NULL,
            10, 10,
            rcClient.right - rcClient.left - 20,
            rcClient.bottom - rcClient.top - 20,
            SWP_NOZORDER | SWP_NOACTIVATE);
    }
    break;

    case WM_TIMER:
        if (wParam == TIMER_ID) {
            UpdateConnections(hListView);
        }
        break;

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == IDC_LISTVIEW && pnmh->code == LVN_COLUMNCLICK) {
            NMLISTVIEW* pnmv = (NMLISTVIEW*)lParam;
            int clickedCol = pnmv->iSubItem;
            if (sortColumn == clickedCol)
                sortAscending = !sortAscending;
            else {
                sortColumn = clickedCol;
                sortAscending = true;
            }
            ListView_SortItems(hListView, CompareFunc, (LPARAM)sortColumn);
        }
    }
    break;

    case WM_DESTROY:
        KillTimer(hwnd, TIMER_ID);
        if (hImageList) {
            ImageList_Destroy(hImageList);
        }
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"NetMonWindow";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, CLASS_NAME, L"NetMonitor",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
