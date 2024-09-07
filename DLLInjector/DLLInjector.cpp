#include <windows.h>
#include <iostream>
#include <filesystem>
#include <string>

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "Invalid args.\n\n"
              << "Usage: DLLInjector.exe <dll_path> <pid>\n"
              << "  dll_path     path to the dll to inject\n"
              << "  pid          pid of the process to inject the dll to\n"
              << '\n';
    std::exit(1);
  }
  const std::string dll_path{argv[1]};
  const int pid{std::stoi(argv[2])};

  if (!std::filesystem::exists(dll_path)) {
    std::cerr << "DLL doesn't exist!\n";
    std::exit(1);
  }

  std::cout << "Injecting " << dll_path << " to " << pid << '\n';

  auto h_proc{OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)};
  if (!h_proc) {
    std::cerr << "Cannot open proc handle. Err: " << GetLastError() << '\n';
    std::exit(1);
  }

  auto p_dll_path{VirtualAllocEx(h_proc, 0, dll_path.size() + 1, MEM_COMMIT,
                                 PAGE_READWRITE)};
  if (!p_dll_path) {
    std::cerr << "Cannot allocate memory in process " << pid
              << ". Err: " << GetLastError() << '\n';
    std::exit(1);
  }

  if (!WriteProcessMemory(h_proc, p_dll_path, dll_path.c_str(),
                          dll_path.size() + 1, nullptr)) {
    std::cerr << "Cannot write to process memory. Err: " << GetLastError()
              << '\n';
    std::exit(1);
  }

  auto load_lib_function_addr{(LPTHREAD_START_ROUTINE)GetProcAddress(
      GetModuleHandleA("Kernel32.dll"), "LoadLibraryA")};
  auto thread{CreateRemoteThread(h_proc, 0, 0, load_lib_function_addr,
                                 p_dll_path, 0, 0)};
  if (!thread) {
    std::cerr << "Cannot create a remote thread. Err: " << GetLastError()
              << '\n';
    std::exit(1);
  }

  WaitForSingleObject(thread, INFINITE);

  std::cout << "Dll injected!\n";

  VirtualFreeEx(h_proc, p_dll_path, dll_path.size() + 1, MEM_RELEASE);
}
