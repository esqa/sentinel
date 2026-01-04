#ifndef SENTINEL_H
#define SENTINEL_H

#include <string_view>

namespace sentinel
{
struct sequence
{
    unsigned char byte;
    bool use;
};

// josh - make sure your input is valid!
int parse_pattern(std::string_view in, sequence *out);

void *find_signature(void *module, sequence *sequence, int length);
} // namespace sentinel

#endif
