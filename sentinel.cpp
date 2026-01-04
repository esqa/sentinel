#include "sentinel.h"

#include <Windows.h>
#include <emmintrin.h>
#include <intrin.h>
#include <cstring>

int char_to_hex(int c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }

    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }

    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }

    return -1;
}

bool simd_compare_16(unsigned char *pattern, unsigned char *memory, unsigned char *mask)
{
    auto pattern_reg = _mm_loadu_si128(reinterpret_cast<__m128i *>(pattern));
    auto memory_reg  = _mm_loadu_si128(reinterpret_cast<__m128i *>(memory));
    auto mask_reg    = _mm_loadu_si128(reinterpret_cast<__m128i *>(mask));

    auto masked_pattern = _mm_and_si128(pattern_reg, mask_reg);
    auto masked_memory  = _mm_and_si128(memory_reg, mask_reg);
    auto comparison     = _mm_cmpeq_epi8(masked_pattern, masked_memory);

    return _mm_movemask_epi8(comparison) == 0xFFFF;
}

bool full_compare(unsigned char *pattern, unsigned char *memory, unsigned char *mask, int length)
{
    int offset = 0;
    while (offset + 16 <= length)
    {
        if (!simd_compare_16(pattern + offset, memory + offset, mask + offset))
        {
            return false;
        }

        offset += 16;
    }

    for (int i = offset; i < length; i++)
    {
        if (mask[i] && memory[i] != pattern[i])
        {
            return false;
        }
    }

    return true;
}

int sentinel::parse_pattern(std::string_view in, sequence *out)
{
    int length = 0;

    for (int i = 0; i < in.length(); i++)
    {
        if (in.data()[i] != ' ')
        {
            if (in.data()[i] == '?')
            {
                out[length].byte = 0;
                out[length].use  = false;
                length++;

                if (i + 1 < in.length() && in.data()[i + 1] == '?')
                {
                    i++;
                }
            }
            else
            {
                out[length].byte = char_to_hex(in.data()[i]) << 4 | char_to_hex(in.data()[i + 1]);
                out[length].use  = true;
                length++;
                i++;
            }
        }
    }

    return length;
}

void *sentinel::find_signature(void *module, sequence *sequence, int length)
{
    auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(module);
    auto nt_header  = reinterpret_cast<IMAGE_NT_HEADERS *>(reinterpret_cast<BYTE *>(module) + dos_header->e_lfanew);

    BYTE *text_start     = nullptr;
    size_t text_size     = 0;
    auto sections = IMAGE_FIRST_SECTION(nt_header);

    // josh - getting the .text section only takes like ~2k cycles it's fine
    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
    {
        char name[9] = {};
        memcpy(name, sections[i].Name, 8);
        if (strcmp(name, ".text") == 0)
        {
            text_start = reinterpret_cast<BYTE *>(module) + sections[i].VirtualAddress;
            text_size  = sections[i].Misc.VirtualSize;
            break;
        }
    }

    unsigned char pattern[length];
    unsigned char mask[length];

    for (int i = 0; i < length; i++)
    {
        pattern[i] = sequence[i].byte;
        mask[i]    = sequence[i].use ? 0xFF : 0x00;
    }

    auto text_end = text_start + text_size;

    int lead_idx = -1;
    for (int i = 0; i < length; i++)
    {
        if (mask[i])
        {
            lead_idx = i;
            break;
        }
    }

    if (lead_idx == -1)
    {
        return text_start;
    }

    auto lead_byte = pattern[lead_idx];
    auto lead_vec = _mm_set1_epi8(lead_byte);

    auto scan_end = text_end - length - 15;
    for (auto p = text_start; p < scan_end; p += 16)
    {
        auto chunk = _mm_loadu_si128(reinterpret_cast<__m128i *>(p + lead_idx));
        auto cmp = _mm_cmpeq_epi8(chunk, lead_vec);
        int match_mask = _mm_movemask_epi8(cmp);

        while (match_mask)
        {
            unsigned long bit_pos{};
            _BitScanForward(&bit_pos, match_mask);

            auto candidate = p + bit_pos;
            if (candidate <= text_end - length)
            {
                if (full_compare(pattern, candidate, mask, length))
                {
                    return candidate;
                }
            }

            match_mask &= match_mask - 1;
        }
    }

    for (auto p = scan_end > text_start ? scan_end : text_start; p <= text_end - length; ++p)
    {
        if (p[lead_idx] == lead_byte)
        {
            if (full_compare(pattern, p, mask, length))
            {
                return p;
            }
        }
    }

    __asm int3;
}