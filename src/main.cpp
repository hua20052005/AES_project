#include "aes_modes.h"
#include <iostream>
#include <unistd.h>
#include <string>

int main(int argc, char** argv) {
    std::string p, k, v, m, c;
    bool bench = false;
    int opt;
    while ((opt = getopt(argc, argv, "p:k:v:m:c:b")) != -1) {
        switch (opt) {
            case 'p': p = optarg; break;
            case 'k': k = optarg; break;
            case 'v': v = optarg; break;
            case 'm': m = optarg; break;
            case 'c': c = optarg; break;
            case 'b': bench = true; break;
            default:
                std::cerr << "Usage: e2aes -p plain -k key [-v iv] -m mode -c cipher [-b benchmark]\n";
                return 1;
        }
    }
    if (bench) {
        benchmark_modes();
    } else {
        if (p.empty() || k.empty() || m.empty() || c.empty()) {
            std::cerr << "Missing parameters\n";
            return 1;
        }
        encrypt_file(p, k, v, m, c);
    }
    return 0;
}
