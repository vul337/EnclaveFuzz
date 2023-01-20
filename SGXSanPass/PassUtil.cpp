#include "PassUtil.h"
#include "llvm/Support/MemoryBuffer.h"
#include <filesystem>

using namespace llvm;
using ordered_json = nlohmann::ordered_json;
using json = nlohmann::json;

void dump(ordered_json json) { dbgs() << json.dump(4) << "\n"; }
void dump(ordered_json json, ordered_json::json_pointer ptr) {
  dbgs() << ptr.to_string() << "\n" << json[ptr].dump(4) << "\n";
}

void dump(json json) { dbgs() << json.dump(4) << "\n"; }
void dump(json json, json::json_pointer ptr) {
  dbgs() << ptr.to_string() << "\n" << json[ptr].dump(4) << "\n";
}

void dump(Value *val) { dbgs() << toString(val) << "\n\n"; }

std::vector<std::string> GetFileNames(std::filesystem::path dir,
                                      std::string substr) {
  std::vector<std::string> fileNames;
  for (auto const &entry : std::filesystem::directory_iterator(dir)) {
    if (std::filesystem::is_regular_file(entry)) {
      auto fileName = entry.path().filename().string();
      if (fileName.find(substr) != fileName.npos) {
        fileNames.push_back(fileName);
      }
    }
  }
  return fileNames;
}

std::string ReadFile(std::string fileName) {
  auto fileBuffer = MemoryBuffer::getFile(fileName);
  if (auto EC = fileBuffer.getError()) {
    errs() << "[ERROR] " << fileName << ": " << EC.message() << "\n";
    abort();
  }
  return fileBuffer->get()->getBuffer().str();
}